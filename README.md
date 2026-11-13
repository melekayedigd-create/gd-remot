# PC Remote v2 (Geode mod)

See the Geometry Dash screen of your Android tablet in Chrome / Edge on your PC and control
everything from there: menus, levels, online, the editor, typing level names, etc.

## Build (GitHub Actions)
1. Upload everything in this folder to a GitHub repo, **including** `.github/workflows/build.yml`
   and `src/stb_image_write.h`.
2. Actions tab -> "Build Geode Mod" -> wait for green -> download **Build Output** -> `myriam.pc-remote.geode`.
3. Install it in Geode on the tablet and restart GD.

## Use
1. Tablet and PC on the same Wi-Fi.
2. Open GD: the main menu shows `PC Remote: 192.168.x.x:7777` at the bottom.
3. On the PC open `http://192.168.x.x:7777` in Chrome / Edge (or open `pc/gd-remote.html` and type the IP).
4. Click the game picture once so your keyboard goes to it.

| PC | Tablet |
|---|---|
| Left click / drag | Tap / drag a finger |
| Right drag | Two-finger drag (pan) |
| Mouse wheel, + / − buttons | Pinch zoom (editor) |
| Space / W / Up | Jump (direct, low delay in levels) |
| A D / Left Right | Move in platformer levels |
| Esc, ◀ Back | Android back (pause, leave menus) |
| Any other key | Sent to GD: editor shortcuts, typing in text fields |

Size / FPS / Quality in the top bar: lower them if the picture lags, raise them on good Wi-Fi.
The ⛶ button goes fullscreen and lets the page catch Esc and Ctrl shortcuts.

## Notes
- Sound stays on the tablet.
- If your GD / Geode versions differ, change `"geode"` and `"gd"` in `mod.json` to match your other mods.
- After editing `pc/gd-remote.html`, run `python make_page.py` to update `src/page.hpp`.
- Anyone on the same Wi-Fi can connect while GD is open, so use it on your home network.
