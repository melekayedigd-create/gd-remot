// PC Remote v2 — stream the tablet screen to a PC browser and control Geometry Dash from it.
//
// The mod runs a small HTTP + WebSocket server on port 7777:
//   * HTTP GET /     -> the control page (same as pc/gd-remote.html)
//   * WebSocket      -> tablet sends JPEG frames, PC sends touches / keys / text
//
// PC -> tablet messages (text):
//   t d|m|u <id> <x> <y>    touch down / move / up, x y normalised 0..1 (top-left origin)
//   k d|r|u <code> <mods>   key down / repeat / up (Windows virtual key code, mods: 1 shift 2 ctrl 4 alt)
//   x <text>                typed text (goes to the focused text field)
//   bs                      backspace in the focused text field
//   back                    Android back button
//   cfg <width> <fps> <q>   video settings
//   ack                     "ready for the next frame"
//   ping <t>                -> pong <t>

#include <Geode/Geode.hpp>
#include <Geode/modify/MenuLayer.hpp>
#include <Geode/modify/CCDirector.hpp>

#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define STB_IMAGE_WRITE_IMPLEMENTATION
#define STBI_WRITE_NO_STDIO
#include "stb_image_write.h"

#include "page.hpp"

using namespace geode::prelude;

static constexpr int REMOTE_PORT = 7777;

// Video settings (changed by the PC page)
static std::atomic<int> g_cfgWidth{854};
static std::atomic<int> g_cfgFps{30};
static std::atomic<int> g_cfgQuality{60};

// ==================================================================
// SHA-1 + Base64 (WebSocket handshake)
// ==================================================================
static std::array<uint8_t, 20> sha1(std::string const& msg) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    std::vector<uint8_t> d(msg.begin(), msg.end());
    uint64_t bitLen = static_cast<uint64_t>(d.size()) * 8;
    d.push_back(0x80);
    while (d.size() % 64 != 56) d.push_back(0);
    for (int i = 7; i >= 0; --i) d.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xff));
    auto rol = [](uint32_t x, int n) { return (x << n) | (x >> (32 - n)); };
    for (size_t off = 0; off < d.size(); off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = (uint32_t(d[off + 4 * i]) << 24) | (uint32_t(d[off + 4 * i + 1]) << 16) |
                   (uint32_t(d[off + 4 * i + 2]) << 8) | uint32_t(d[off + 4 * i + 3]);
        }
        for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], dd = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | (~b & dd);           k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ dd;                    k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & dd) | (c & dd); k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ dd;                    k = 0xCA62C1D6; }
            uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = dd; dd = c; c = rol(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += dd; h[4] += e;
    }
    std::array<uint8_t, 20> out{};
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (h[i] >> 24) & 0xff; out[i * 4 + 1] = (h[i] >> 16) & 0xff;
        out[i * 4 + 2] = (h[i] >> 8) & 0xff; out[i * 4 + 3] = h[i] & 0xff;
    }
    return out;
}

static std::string base64(uint8_t const* data, size_t len) {
    static char const* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = uint32_t(data[i]) << 16;
        if (i + 1 < len) n |= uint32_t(data[i + 1]) << 8;
        if (i + 2 < len) n |= uint32_t(data[i + 2]);
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += (i + 1 < len) ? tbl[(n >> 6) & 63] : '=';
        out += (i + 2 < len) ? tbl[n & 63] : '=';
    }
    return out;
}

// ==================================================================
// Network helpers
// ==================================================================
static bool sendAll(int fd, void const* buf, size_t len) {
    auto p = static_cast<char const*>(buf);
    while (len > 0) {
        ssize_t n = ::send(fd, p, len, MSG_NOSIGNAL);
        if (n <= 0) return false;
        p += n; len -= static_cast<size_t>(n);
    }
    return true;
}

static bool recvExact(int fd, void* buf, size_t len) {
    auto p = static_cast<char*>(buf);
    while (len > 0) {
        ssize_t n = ::recv(fd, p, len, 0);
        if (n <= 0) return false;
        p += n; len -= static_cast<size_t>(n);
    }
    return true;
}

static bool wsSend(int fd, uint8_t opcode, char const* data, size_t size) {
    uint8_t hdr[10];
    size_t hl = 0;
    hdr[hl++] = 0x80 | opcode;
    if (size < 126) {
        hdr[hl++] = static_cast<uint8_t>(size);
    } else if (size <= 0xffff) {
        hdr[hl++] = 126;
        hdr[hl++] = (size >> 8) & 0xff;
        hdr[hl++] = size & 0xff;
    } else {
        hdr[hl++] = 127;
        for (int i = 7; i >= 0; --i) hdr[hl++] = (static_cast<uint64_t>(size) >> (i * 8)) & 0xff;
    }
    return sendAll(fd, hdr, hl) && (size == 0 || sendAll(fd, data, size));
}

static std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static std::string headerValue(std::string const& req, std::string const& name) {
    auto low = lower(req);
    auto pos = low.find("\r\n" + lower(name) + ":");
    if (pos == std::string::npos) return "";
    pos += name.size() + 3;
    auto end = req.find("\r\n", pos);
    auto v = req.substr(pos, end - pos);
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(v.begin());
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.pop_back();
    return v;
}

static std::vector<std::string> localIPs() {
    // SIOCGIFCONF works on every Android version (getifaddrs needs Android 7+)
    std::vector<std::string> ips;
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return ips;
    char buf[4096];
    ifconf ifc{};
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(s, SIOCGIFCONF, &ifc) == 0) {
        for (auto* it = ifc.ifc_req; reinterpret_cast<char*>(it + 1) <= buf + ifc.ifc_len; ++it) {
            if (it->ifr_addr.sa_family != AF_INET) continue;
            auto sin = reinterpret_cast<sockaddr_in*>(&it->ifr_addr);
            char ip[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip))) continue;
            std::string addr(ip);
            if (addr.rfind("127.", 0) == 0) continue; // skip loopback
            ips.push_back(addr);
        }
    }
    ::close(s);
    return ips;
}

// ==================================================================
// Connected PCs
// ==================================================================
struct Client {
    int fd;
    std::mutex sendMtx;
    static constexpr int MAX_IN_FLIGHT = 2;
    std::atomic<int> credits{MAX_IN_FLIGHT}; // frames we may send before the PC acks
    bool sendText(std::string const& s) {
        std::lock_guard lock(sendMtx);
        return wsSend(fd, 0x1, s.data(), s.size());
    }
    bool sendBinary(std::string const& s) {
        std::lock_guard lock(sendMtx);
        return wsSend(fd, 0x2, s.data(), s.size());
    }
};

static std::mutex g_clientsMtx;
static std::vector<std::shared_ptr<Client>> g_clients;

static bool anyClientReady() {
    std::lock_guard lock(g_clientsMtx);
    for (auto& c : g_clients) if (c->credits > 0) return true;
    return false;
}

// ==================================================================
// Input injection (main thread only)
// The `if constexpr (requires ...)` blocks adapt to small API differences between GD/Geode versions.
// ==================================================================
// Same clock Android uses for input events (seconds since boot, monotonic)
static double inputTimestamp() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return double(ts.tv_sec) + double(ts.tv_nsec) / 1e9;
}

template <class View>
static void injectTouch(View* view, char phase, int id, float x, float y) {
    if (!view) return;
    double t = inputTimestamp();
    if constexpr (requires { view->handleTouchesBegin(1, &id, &x, &y, t); }) {
        if (phase == 'd') view->handleTouchesBegin(1, &id, &x, &y, t);
        else if (phase == 'm') view->handleTouchesMove(1, &id, &x, &y, t);
        else view->handleTouchesEnd(1, &id, &x, &y, t);
    } else if constexpr (requires { view->handleTouchesBegin(1, &id, &x, &y); }) {
        if (phase == 'd') view->handleTouchesBegin(1, &id, &x, &y);
        else if (phase == 'm') view->handleTouchesMove(1, &id, &x, &y);
        else view->handleTouchesEnd(1, &id, &x, &y);
    }
}

template <class Dir>
static void injectKey(Dir* dir, int code, bool down, bool repeat, int mods) {
    auto kd = dir->getKeyboardDispatcher();
    if (!kd) return;
    bool shift = mods & 1, ctrl = mods & 2, alt = mods & 4;
    if constexpr (requires { kd->updateModifierKeys(shift, ctrl, alt, false); }) {
        kd->updateModifierKeys(shift, ctrl, alt, false);
    }
    auto key = static_cast<enumKeyCodes>(code);
    if constexpr (requires { kd->dispatchKeyboardMSG(key, down, repeat, 0.0); }) {
        kd->dispatchKeyboardMSG(key, down, repeat, inputTimestamp());
    } else if constexpr (requires { kd->dispatchKeyboardMSG(key, down, repeat); }) {
        kd->dispatchKeyboardMSG(key, down, repeat);
    } else if constexpr (requires { kd->dispatchKeyboardMSG(key, down); }) {
        kd->dispatchKeyboardMSG(key, down);
    }
}

template <class Ime>
static void imeInsert(Ime* ime, std::string const& text) {
    if (!ime || text.empty()) return;
    auto noKey = static_cast<enumKeyCodes>(0);
    if constexpr (requires { ime->dispatchInsertText(text.c_str(), int(text.size()), noKey); }) {
        ime->dispatchInsertText(text.c_str(), int(text.size()), noKey);
    } else if constexpr (requires { ime->dispatchInsertText(text.c_str(), int(text.size())); }) {
        ime->dispatchInsertText(text.c_str(), int(text.size()));
    }
}

template <class Ime>
static void imeBackspace(Ime* ime) {
    if (!ime) return;
    if constexpr (requires { ime->dispatchDeleteBackward(); }) ime->dispatchDeleteBackward();
}

// --- gameplay buttons: sent straight to the level for the lowest delay ---
struct HeldKey {
    int button; bool p1;
    bool operator<(HeldKey const& o) const { return button != o.button ? button < o.button : p1 < o.p1; }
};
static std::set<HeldKey> g_held;
static std::set<int> g_gameplayKeysDown;   // key codes currently routed to handleButton
static std::set<int> g_keysDown;           // key codes currently routed to the keyboard dispatcher
static std::set<int> g_touchesDown;
static float g_lastTouchX = 0, g_lastTouchY = 0;

static PauseLayer* findPauseLayer() {
    auto scene = CCDirector::get()->getRunningScene();
    return scene ? scene->getChildByType<PauseLayer>(0) : nullptr;
}

static bool gameplayButtonFor(int code, int& button) {
    switch (code) {
        case 32: case 38: case 87: button = 1; return true; // Space, Up, W -> jump
        case 37: case 65:          button = 2; return true; // Left, A     -> left
        case 39: case 68:          button = 3; return true; // Right, D    -> right
        default: return false;
    }
}

static void gameButton(int button, bool p1, bool down) {
    auto pl = PlayLayer::get();
    if (!pl) return;
    HeldKey key{button, p1};
    if (down) { if (!g_held.insert(key).second) return; }
    else { if (!g_held.erase(key)) return; }
    pl->handleButton(down, button, p1);
}

static void releaseAllInput() {
    if (auto pl = PlayLayer::get()) for (auto const& k : g_held) pl->handleButton(false, k.button, k.p1);
    g_held.clear();
    g_gameplayKeysDown.clear();
    auto dir = CCDirector::get();
    for (int code : g_keysDown) injectKey(dir, code, false, false, 0);
    g_keysDown.clear();
    auto view = dir->getOpenGLView();
    for (int id : g_touchesDown) injectTouch(view, 'u', id, g_lastTouchX, g_lastTouchY);
    g_touchesDown.clear();
}

static void handleKey(char phase, int code, int mods) {
    auto dir = CCDirector::get();
    int button;
    bool playing = PlayLayer::get() && !findPauseLayer();

    if (phase == 'u') {
        if (g_gameplayKeysDown.erase(code)) {
            gameplayButtonFor(code, button);
            // release only when no other key for the same button is still held
            bool other = false;
            for (int c : g_gameplayKeysDown) { int b; if (gameplayButtonFor(c, b) && b == button) other = true; }
            if (!other) gameButton(button, true, false);
            return;
        }
        if (g_keysDown.erase(code)) injectKey(dir, code, false, false, mods);
        return;
    }

    if (playing && gameplayButtonFor(code, button)) {
        if (phase == 'd') { g_gameplayKeysDown.insert(code); gameButton(button, true, true); }
        return;
    }
    if (phase == 'd') g_keysDown.insert(code);
    injectKey(dir, code, true, phase == 'r', mods);
}

static void handleCommand(std::string const& cmd) {
    std::istringstream in(cmd);
    std::string op;
    in >> op;

    if (op == "t") {
        std::string phase; int id; float nx, ny;
        if (!(in >> phase >> id >> nx >> ny) || phase.empty()) return;
        auto view = CCDirector::get()->getOpenGLView();
        if (!view) return;
        auto size = view->getFrameSize();
        float x = nx * size.width, y = ny * size.height;
        g_lastTouchX = x; g_lastTouchY = y;
        char p = phase[0];
        if (p == 'd') { if (g_touchesDown.count(id)) injectTouch(view, 'u', id, x, y); g_touchesDown.insert(id); }
        if (p == 'u') { if (!g_touchesDown.erase(id)) return; }
        if (p == 'm' && !g_touchesDown.count(id)) return;
        injectTouch(view, p, id, x, y);
    }
    else if (op == "k") {
        std::string phase; int code = 0, mods = 0;
        if (!(in >> phase >> code) || phase.empty()) return;
        in >> mods;
        handleKey(phase[0], code, mods);
    }
    else if (op == "x") {
        imeInsert(CCIMEDispatcher::sharedDispatcher(), cmd.size() > 2 ? cmd.substr(2) : std::string());
    }
    else if (op == "bs") {
        imeBackspace(CCIMEDispatcher::sharedDispatcher());
    }
    else if (op == "back") {
        releaseAllInput();
        CCDirector::get()->getKeypadDispatcher()->dispatchKeypadMSG(kTypeBackClicked);
    }
    else if (op == "release") {
        releaseAllInput();
    }
}

// ==================================================================
// Screen capture (main thread, right after the frame is drawn)
// GPU path: copy the frame into a texture, draw it shrunk into a small framebuffer, read that back.
// Fallback: read the full frame and shrink it on the CPU.
// ==================================================================
struct FrameJob {
    std::vector<uint8_t> rgba; // bottom-up rows, as OpenGL returns them
    int w = 0, h = 0;
    int dstW = 0, dstH = 0;    // final size (CPU path shrinks to this)
    float captureMs = 0;       // time spent on the game thread
    bool gpu = false;          // which capture path was used
};

static std::mutex g_jobMtx;
static std::condition_variable g_jobCv;
static std::unique_ptr<FrameJob> g_job;           // waiting for the encoder
static std::atomic<bool> g_encoderBusy{false};
static std::vector<uint8_t> g_spareBuffer;

struct GpuCapture {
    GLuint fullTex = 0, smallTex = 0, fbo = 0;
    int fullW = 0, fullH = 0, smallW = 0, smallH = 0;
    bool failed = false;

    void release() {
        if (fbo) glDeleteFramebuffers(1, &fbo);
        if (smallTex) glDeleteTextures(1, &smallTex);
        if (fullTex) glDeleteTextures(1, &fullTex);
        fbo = smallTex = fullTex = 0;
        fullW = fullH = smallW = smallH = 0;
    }

    bool setup(int fw, int fh, int sw, int sh) {
        if (fw == fullW && fh == fullH && sw == smallW && sh == smallH && fbo) return true;
        release();
        GLint oldFbo = 0;
        glGetIntegerv(GL_FRAMEBUFFER_BINDING, &oldFbo);

        glGenTextures(1, &fullTex);
        ccGLBindTexture2D(fullTex);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, fw, fh, 0, GL_RGB, GL_UNSIGNED_BYTE, nullptr);

        glGenTextures(1, &smallTex);
        ccGLBindTexture2D(smallTex);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, sw, sh, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);

        glGenFramebuffers(1, &fbo);
        glBindFramebuffer(GL_FRAMEBUFFER, fbo);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, smallTex, 0);
        bool ok = glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
        glBindFramebuffer(GL_FRAMEBUFFER, oldFbo);
        ccGLBindTexture2D(0);

        if (!ok) { log::warn("PC Remote: GPU capture unavailable, using CPU path"); release(); return false; }
        fullW = fw; fullH = fh; smallW = sw; smallH = sh;
        return true;
    }

    bool capture(int fw, int fh, int sw, int sh, std::vector<uint8_t>& out) {
        if (failed || !setup(fw, fh, sw, sh)) { failed = true; return false; }
        while (glGetError() != GL_NO_ERROR) {}

        GLint oldFbo = 0, vp[4];
        glGetIntegerv(GL_FRAMEBUFFER_BINDING, &oldFbo);
        glGetIntegerv(GL_VIEWPORT, vp);
        GLboolean scissor = glIsEnabled(GL_SCISSOR_TEST);
        GLboolean depth = glIsEnabled(GL_DEPTH_TEST);

        // 1. copy the finished frame into fullTex
        ccGLBindTexture2D(fullTex);
        glCopyTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 0, 0, fw, fh);

        // 2. draw it shrunk into the small framebuffer
        glBindFramebuffer(GL_FRAMEBUFFER, fbo);
        glViewport(0, 0, sw, sh);
        if (scissor) glDisable(GL_SCISSOR_TEST);
        if (depth) glDisable(GL_DEPTH_TEST);

        auto prog = CCShaderCache::sharedShaderCache()->programForKey(kCCShader_PositionTexture);
        prog->use();
        kmGLMatrixMode(KM_GL_PROJECTION); kmGLPushMatrix(); kmGLLoadIdentity();
        kmGLMatrixMode(KM_GL_MODELVIEW);  kmGLPushMatrix(); kmGLLoadIdentity();
        prog->setUniformsForBuiltins();
        ccGLEnableVertexAttribs(kCCVertexAttribFlag_Position | kCCVertexAttribFlag_TexCoords);
        ccGLBlendFunc(GL_ONE, GL_ZERO);
        glBindBuffer(GL_ARRAY_BUFFER, 0);
        static GLfloat const verts[] = {-1.f, -1.f, 1.f, -1.f, -1.f, 1.f, 1.f, 1.f};
        static GLfloat const uvs[]   = { 0.f,  0.f, 1.f,  0.f,  0.f, 1.f, 1.f, 1.f};
        glVertexAttribPointer(kCCVertexAttrib_Position, 2, GL_FLOAT, GL_FALSE, 0, verts);
        glVertexAttribPointer(kCCVertexAttrib_TexCoords, 2, GL_FLOAT, GL_FALSE, 0, uvs);
        glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);

        // 3. read the small image
        out.resize(size_t(sw) * sh * 4);
        glReadPixels(0, 0, sw, sh, GL_RGBA, GL_UNSIGNED_BYTE, out.data());

        // restore everything cocos expects
        kmGLMatrixMode(KM_GL_MODELVIEW);  kmGLPopMatrix();
        kmGLMatrixMode(KM_GL_PROJECTION); kmGLPopMatrix();
        kmGLMatrixMode(KM_GL_MODELVIEW);
        glBindFramebuffer(GL_FRAMEBUFFER, oldFbo);
        glViewport(vp[0], vp[1], vp[2], vp[3]);
        if (scissor) glEnable(GL_SCISSOR_TEST);
        if (depth) glEnable(GL_DEPTH_TEST);
        ccGLBindTexture2D(0);
        ccGLBlendFunc(CC_BLEND_SRC, CC_BLEND_DST);

        if (glGetError() != GL_NO_ERROR) {
            log::warn("PC Remote: GPU capture failed, switching to CPU path");
            failed = true;
            release();
            return false;
        }
        return true;
    }
};

static GpuCapture g_gpu;
static auto g_lastCapture = std::chrono::steady_clock::now();

static void captureFrame() {
    {
        std::lock_guard lock(g_clientsMtx);
        if (g_clients.empty()) {
            if (g_gpu.fbo) g_gpu.release();
            return;
        }
    }
    auto now = std::chrono::steady_clock::now();
    int fps = std::clamp(g_cfgFps.load(), 1, 60);
    if (now - g_lastCapture < std::chrono::microseconds(1000000 / fps - 2000)) return;
    if (!anyClientReady()) return;
    {
        std::lock_guard lock(g_jobMtx);
        if (g_job) return;
    }

    auto view = CCDirector::get()->getOpenGLView();
    if (!view) return;
    auto frame = view->getFrameSize();
    int fw = int(frame.width), fh = int(frame.height);
    if (fw <= 0 || fh <= 0) return;

    int dw = std::clamp(g_cfgWidth.load(), 320, 1920);
    if (dw > fw) dw = fw;
    int dh = int(float(dw) * fh / fw) & ~1;
    dw &= ~1;

    auto job = std::make_unique<FrameJob>();
    job->rgba.swap(g_spareBuffer);
    job->dstW = dw; job->dstH = dh;

    auto t0 = std::chrono::steady_clock::now();
    if (g_gpu.capture(fw, fh, dw, dh, job->rgba)) {
        job->w = dw; job->h = dh;
        job->gpu = true;
    } else {
        // CPU path: read the full frame, the encoder thread shrinks it
        job->rgba.resize(size_t(fw) * fh * 4);
        glPixelStorei(GL_PACK_ALIGNMENT, 4);
        glReadPixels(0, 0, fw, fh, GL_RGBA, GL_UNSIGNED_BYTE, job->rgba.data());
        job->w = fw; job->h = fh;
    }
    job->captureMs = std::chrono::duration<float, std::milli>(std::chrono::steady_clock::now() - t0).count();
    g_lastCapture = now;

    {
        std::lock_guard lock(g_jobMtx);
        g_job = std::move(job);
    }
    g_jobCv.notify_one();
}

class $modify(PCRemoteDirector, CCDirector) {
    void drawScene() {
        CCDirector::drawScene();
        // On Android the frame is still in the back buffer here (it's swapped after this returns)
        captureFrame();
    }
};

// ==================================================================
// Encoder thread: shrink (if needed), flip, JPEG, send
// ==================================================================
static void jpegWrite(void* ctx, void* data, int size) {
    static_cast<std::string*>(ctx)->append(static_cast<char*>(data), size_t(size));
}

static void encoderLoop() {
    std::vector<uint8_t> rgb;
    std::string jpeg;
    while (true) {
        std::unique_ptr<FrameJob> job;
        {
            std::unique_lock lock(g_jobMtx);
            g_jobCv.wait(lock, [] { return g_job != nullptr; });
            job = std::move(g_job);
            g_encoderBusy = true;
        }

        int dw = job->dstW, dh = job->dstH, sw = job->w, sh = job->h;
        rgb.resize(size_t(dw) * dh * 3);
        uint8_t const* src = job->rgba.data();
        if (sw == dw && sh == dh) {
            for (int y = 0; y < dh; y++) {
                uint8_t const* s = src + size_t(dh - 1 - y) * dw * 4; // flip vertically
                uint8_t* d = rgb.data() + size_t(y) * dw * 3;
                for (int x = 0; x < dw; x++) { d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d += 3; s += 4; }
            }
        } else {
            // box-ish shrink: average 2x2 source pixels around each sample point
            for (int y = 0; y < dh; y++) {
                int sy = std::min(sh - 2, int((dh - 1 - y) * float(sh) / dh));
                uint8_t* d = rgb.data() + size_t(y) * dw * 3;
                for (int x = 0; x < dw; x++) {
                    int sx = std::min(sw - 2, int(x * float(sw) / dw));
                    uint8_t const* p0 = src + (size_t(sy) * sw + sx) * 4;
                    uint8_t const* p1 = p0 + size_t(sw) * 4;
                    for (int c = 0; c < 3; c++) d[c] = uint8_t((p0[c] + p0[c + 4] + p1[c] + p1[c + 4]) >> 2);
                    d += 3;
                }
            }
        }

        // Encode horizontal strips on several cores at once, then send them together.
        // Message: [u16 W][u16 H][u8 strips][u16 captureMs*10][u16 encodeMs*10][u8 flags]
        //          then per strip: [u16 y][u16 h][u32 len][jpeg bytes]
        auto tEnc = std::chrono::steady_clock::now();
        int quality = std::clamp(g_cfgQuality.load(), 10, 95);
        unsigned cores = std::max(1u, std::thread::hardware_concurrency());
        int strips = std::clamp(int(cores) - 1, 1, 4);
        int stripH = std::max(16, (dh / strips + 15) & ~15);
        strips = (dh + stripH - 1) / stripH;
        std::vector<std::string> parts(strips);
        {
            std::vector<std::thread> workers;
            for (int i = 0; i < strips; i++) {
                workers.emplace_back([&, i] {
                    int y0 = i * stripH, h = std::min(stripH, dh - y0);
                    stbi_write_jpg_to_func(jpegWrite, &parts[i], dw, h, 3, rgb.data() + size_t(y0) * dw * 3, quality);
                });
            }
            for (auto& w : workers) w.join();
        }
        float encodeMs = std::chrono::duration<float, std::milli>(std::chrono::steady_clock::now() - tEnc).count();

        auto put16 = [](std::string& o, uint32_t v) { o += char(v & 0xff); o += char((v >> 8) & 0xff); };
        auto put32 = [&](std::string& o, uint32_t v) { put16(o, v & 0xffff); put16(o, v >> 16); };
        jpeg.clear();
        put16(jpeg, dw); put16(jpeg, dh);
        jpeg += char(strips);
        put16(jpeg, uint32_t(std::min(6500.f, job->captureMs) * 10));
        put16(jpeg, uint32_t(std::min(6500.f, encodeMs) * 10));
        jpeg += char(job->gpu ? 1 : 0);
        for (int i = 0; i < strips; i++) {
            put16(jpeg, i * stripH);
            put16(jpeg, std::min(stripH, dh - i * stripH));
            put32(jpeg, uint32_t(parts[i].size()));
            jpeg += parts[i];
        }

        std::vector<std::shared_ptr<Client>> targets;
        {
            std::lock_guard lock(g_clientsMtx);
            for (auto& c : g_clients) if (c->credits > 0) targets.push_back(c);
        }
        for (auto& c : targets) {
            c->credits--;
            if (!c->sendBinary(jpeg)) ::shutdown(c->fd, SHUT_RDWR);
        }

        {
            std::lock_guard lock(g_jobMtx);
            if (g_spareBuffer.empty()) g_spareBuffer.swap(job->rgba);
        }
        g_encoderBusy = false;
    }
}

// ==================================================================
// Client connection
// ==================================================================
static void runWebSocket(int fd) {
    auto client = std::make_shared<Client>();
    client->fd = fd;
    size_t count;
    {
        std::lock_guard lock(g_clientsMtx);
        g_clients.push_back(client);
        count = g_clients.size();
    }
    queueInMainThread([count] {
        Notification::create(fmt::format("PC connected ({})", count), NotificationIcon::Success)->show();
    });
    client->sendText("hello pc-remote 2");

    while (true) {
        uint8_t hdr[2];
        if (!recvExact(fd, hdr, 2)) break;
        uint8_t opcode = hdr[0] & 0x0f;
        bool masked = hdr[1] & 0x80;
        uint64_t len = hdr[1] & 0x7f;
        if (len == 126) {
            uint8_t ext[2];
            if (!recvExact(fd, ext, 2)) break;
            len = (uint64_t(ext[0]) << 8) | ext[1];
        } else if (len == 127) {
            uint8_t ext[8];
            if (!recvExact(fd, ext, 8)) break;
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | ext[i];
        }
        if (len > 64 * 1024) break;
        uint8_t mask[4] = {0, 0, 0, 0};
        if (masked && !recvExact(fd, mask, 4)) break;
        std::string payload(size_t(len), '\0');
        if (len > 0 && !recvExact(fd, payload.data(), payload.size())) break;
        if (masked) for (size_t i = 0; i < payload.size(); i++) payload[i] ^= mask[i % 4];

        if (opcode == 0x8) { std::lock_guard l(client->sendMtx); wsSend(fd, 0x8, nullptr, 0); break; }
        if (opcode == 0x9) { std::lock_guard l(client->sendMtx); wsSend(fd, 0xA, payload.data(), payload.size()); continue; }
        if (opcode != 0x1) continue;

        if (payload == "ack") {
            int c = client->credits.load();
            while (c < Client::MAX_IN_FLIGHT && !client->credits.compare_exchange_weak(c, c + 1)) {}
            continue;
        }
        if (payload.rfind("ping ", 0) == 0) { client->sendText("pong " + payload.substr(5)); continue; }
        if (payload.rfind("cfg ", 0) == 0) {
            std::istringstream in(payload.substr(4));
            int w, f, q;
            if (in >> w >> f >> q) { g_cfgWidth = w; g_cfgFps = f; g_cfgQuality = q; }
            continue;
        }
        queueInMainThread([payload] { handleCommand(payload); });
    }

    {
        std::lock_guard lock(g_clientsMtx);
        std::erase(g_clients, client);
    }
    queueInMainThread([] {
        releaseAllInput();
        Notification::create("PC disconnected", NotificationIcon::Info)->show();
    });
}

static void handleClient(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    timeval tv{3, 0}; // a frozen PC must not block the encoder forever
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    std::string req;
    char buf[1024];
    while (req.find("\r\n\r\n") == std::string::npos && req.size() < 16 * 1024) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) { ::close(fd); return; }
        req.append(buf, size_t(n));
    }

    auto key = headerValue(req, "Sec-WebSocket-Key");
    if (!key.empty()) {
        auto digest = sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        std::string resp =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + base64(digest.data(), digest.size()) + "\r\n\r\n";
        if (sendAll(fd, resp.data(), resp.size())) runWebSocket(fd);
        ::close(fd);
        return;
    }

    bool isRoot = req.rfind("GET / ", 0) == 0 || req.rfind("GET /index.html ", 0) == 0;
    std::string body = isRoot ? std::string(PC_REMOTE_PAGE) : std::string("Not found");
    std::string resp =
        std::string(isRoot ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 404 Not Found\r\n") +
        (isRoot ? "Content-Type: text/html; charset=utf-8\r\n" : "Content-Type: text/plain\r\n") +
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n" + body;
    sendAll(fd, resp.data(), resp.size());
    ::close(fd);
}

// ==================================================================
// Server
// ==================================================================
static std::atomic<bool> g_serverStarted{false};

static void startServer() {
    if (g_serverStarted.exchange(true)) return;
    std::thread(encoderLoop).detach();
    std::thread([] {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { log::error("PC Remote: socket() failed"); return; }
        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(REMOTE_PORT);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            log::error("PC Remote: bind() on port {} failed: {}", REMOTE_PORT, std::strerror(errno));
            ::close(fd);
            return;
        }
        if (::listen(fd, 8) < 0) { ::close(fd); return; }
        log::info("PC Remote: listening on port {}", REMOTE_PORT);
        while (true) {
            int client = ::accept(fd, nullptr, nullptr);
            if (client < 0) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); continue; }
            std::thread(handleClient, client).detach();
        }
    }).detach();
}

// ==================================================================
// Main menu: start the server and show the address
// ==================================================================
class $modify(PCRemoteMenuLayer, MenuLayer) {
    bool init() {
        if (!MenuLayer::init()) return false;
        startServer();

        auto ips = localIPs();
        std::string text;
        if (ips.empty()) {
            text = "PC Remote: no Wi-Fi address found";
        } else {
            text = "PC Remote: ";
            for (size_t i = 0; i < ips.size(); i++) {
                if (i) text += "  |  ";
                text += ips[i] + ":" + std::to_string(REMOTE_PORT);
            }
        }

        auto winSize = CCDirector::get()->getWinSize();
        auto label = CCLabelBMFont::create(text.c_str(), "bigFont.fnt");
        label->setScale(0.35f);
        label->setAnchorPoint({0.5f, 0.f});
        label->setPosition({winSize.width / 2.f, 3.f});
        label->setOpacity(200);
        label->setID("pc-remote-address"_spr);
        this->addChild(label, 100);
        return true;
    }
};
