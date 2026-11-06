# Hardened fork of Pixelorama-MCP

Fork of [abidoo22/Pixelorama-MCP](https://github.com/abidoo22/Pixelorama-MCP) at `56fd8aa` (2026-10-10), branch `hardened`.
Upstream exposed an unauthenticated loopback HTTP bridge with `Access-Control-Allow-Origin: *` and an
`eval`-style tool that compiled and ran arbitrary GDScript inside Pixelorama, so any web page open in a
browser could reach code execution on the machine. This fork closes that path and keeps the drawing API.

## Changes
| Area | Upstream | Hardened |
|---|---|---|
| Arbitrary code tool | compiled agent-supplied GDScript (bridge + MCP tool) | removed from bridge registry, handler and MCP tool list |
| Authentication | none | random 64-hex token in `~/.pixelorama-mcp/token` (0600, created on first start); header `X-Pix-Mcp-Token`, constant-time compare; only `GET /health` is open |
| Browser / CSRF | CORS `*`, `OPTIONS` answered, any Content-Type | requests carrying `Origin`, `Referer` or any `Sec-Fetch-*` are refused (403) as soon as the headers arrive, before any body is read; no `Access-Control-*` headers; `OPTIONS` is never answered (401 without token, 405 with); `POST` must be `application/json` (415) |
| DNS rebinding | Host not checked | `Host` must be `127.0.0.1:7373` or `localhost:7373` (403) |
| File access | any absolute path for save/open/export/import | `~/.pixelorama-mcp/config.json`: `allowed_roots` (write+read) and `read_roots` (read-only: `open_project`, `import_spritesheet`, `import_image`); fail-closed when absent. Every path must be absolute, with no `.`/`..` component on the raw string, no hidden (dot) component, no symlink below the root, dangling links included (bridge: component-wise `is_link` before any existence check; MCP: realpath + `lstat` per component). Name-like parameters that become file names (`prefix`, `base_name`, `sprite_name`, …, and `name` only for palette tools) may not contain separators or control characters; layer/canvas names may contain `/`. `save_project` needs an explicit path. Godot `.tres` identifiers: 1-64 letters/digits of any script, `_`, `-`, inner spaces (no quotes, brackets, `/`, newlines) |
| Request size / slow clients | body length unchecked, 120 s per connection on a single accept loop | headers ≤ 16 KB within 2 s, body ≤ 4 MB within 30 s (413/431); GET never waits for a body (a fake `Content-Length` on `/health` used to hold the single accept loop). Several stalled sockets still serialise for ~2 s each (availability only) |
| MCP client | `fetch` to `PIX_MCP_BRIDGE_URL` (any host) | `node:http`, loopback URLs only (startup error otherwise), token attached |
| Shipped binaries/scripts | prebuilt `PixMcpBridge.pck`, 6 MB `Pixelorama.pck`, `start_pixelorama.sh` (`kill -9`, `rm -rf` on author paths), ad-hoc test scripts | removed; `pack.gd` builds `PixMcpBridge.pck` from source only and copies nothing |
| Project files | `open_project` passed any file to Pixelorama's loader | pre-scan of `.pxo` (see Opening files) for `open_project` **and** for files a person opens in the GUI (open guard) |
| Pixelorama 1.2.4 compatibility | cels assumed canvas-sized; 1.2.4 cels are sparse (used rect + `offset`, empty = 1x1) so draws/reads silently did nothing | `_norm(cel)` expands a cel to canvas size at offset 0 before use (content unchanged, offset/size are in undo data) |

## Opening files (MCP and GUI)
Pixelorama 1.2.4 runs code from files it opens. Reproduced 2026-11-06 with benign payloads that only write a marker file, each opened the way a person does (`open -a Pixelorama FILE`, a fresh process per file), with this extension and guard off:

| Payload | Upstream 1.2.4 | With the guard |
|---|---|---|
| `.pxo` with a 3D-layer `scene/0` holding an inline `[sub_resource type="GDScript"]` (passes the upstream substring guard `'resource type="Script"'`) | **ran** | blocked |
| `.pxo` layer-effect param `Resource("/abs/x.tres")` (`str_to_var` loads the file; its inline script's `_init` runs; also measured directly in Godot 4.7.2) | **ran** | blocked |
| `.pxo` layer-effect `shader_path` pointing at a `.tres` (`LayerEffect.deserialize` `load()`s it) | **ran** | blocked |
| `.tres` given to the app | not run (Godot aborts on a `.tres` command-line argument; File > Open / drop would `load()` it) | refused |
| `.ora` with `Resource(...)` in `stack.xml` `w`, plain and as `Resource&#40;…` | not run with this payload | refused (scanned) |

Pre-scan (`security.gd` `check_pxo`, shared by `open_project` and the guard): `.pxo` extension, zip format only (legacy v0 refused), no `scene/` entries, cel `image_size` / tileset `tile_size` plain integer pairs, every effect `shader_path` a `res://` or `user://` `.gdshader`/`.gdshaderinc` without `..`, and no `Object` or `Resource` constructor name (with or without `(`; covers `SubResource`/`ExtResource`/`Array[Resource]`) in any key or string of `data.json`. Trade-off: a genuine project whose layer effects carry texture/object parameters is refused as well. Other files (`check_open_file`): `.tres`, `.pck`, `.zip` refused (extensions are installed only by `scripts/dev_reload.sh`); `.ora`/`.kra` XML (after entity decoding; numeric character references refused) and palette `.json` scanned for the same names.

**Open guard.** All GUI entry points (Finder / `open -a` / double-click / Dock drop, File > Open, recent projects, drag & drop onto the window, backup restore) end in `OpenSave.handle_loading_file()` or `OpenSave.open_pxo_file()`. `guard_install.gd` swaps the `OpenSave` autoload's script for `open_guard.gd` (a subclass running the pre-scan first; member values copied) and the refusal is shown as a Pixelorama error dialog. On macOS every Finder-style open starts a **new** Pixelorama process with the file on the command line, opened from `Main._ready()` one frame before extension nodes exist, so the guard is installed at boot: `boot_guard.gd` is an autoload registered in `user://override.cfg` (Pixelorama's `project_settings_override`), with the four guard scripts copied to `user://pix_mcp_guard/`. Pixelorama rewrites `override.cfg` from scratch when some preferences change (single-window mode, window transparency, dummy audio); the extension then installs the guard at runtime, re-checks files opened at start-up (error dialog if one would have been refused) and restores the line for the next start. `/health` reports `open_guard`: `boot`, `runtime` or `off`; `scripts/dev_reload.sh` installs both parts and fails unless it is `boot`. Remove the guard: delete the `PixMcpOpenGuard=` line from `override.cfg` and `user://pix_mcp_guard/`.

## Build and install (macOS)
```bash
cd mcp-server && npm ci --ignore-scripts && npm run build && cd ..
# GIF exporter shaders from the official Pixelorama source (MIT), tag matching your Pixelorama:
#   pixelorama-source/addons/gdgifexporter/lookup_similar.gdshader, lookup_color.gdshader
godot --headless --script pack.gd          # -> PixMcpBridge.pck (reproducible: same sources -> same SHA-256)
scripts/dev_reload.sh                      # install into Pixelorama, restart safely, wait for the bridge
```
Create `~/.pixelorama-mcp/config.json` (mode 0600): `{"allowed_roots": ["/abs/write/dir"], "read_roots": ["/abs/project"]}`.

## Tests (need a running Pixelorama with the extension)
```bash
node tests/security_test.mjs --allowed-dir <write dir> --read-only-png <png in a read root>   # 35 checks
node tests/mcp_e2e.mjs --allowed-dir <write dir> --import-png <png in a read root>          # 14 checks via MCP stdio
python3 tests/pxo_test.py <write dir>        # 10 checks: open_project pre-scan
python3 tests/open_guard_test.py <write dir> # 11 checks: GUI opens in fresh instances (stops and restarts Pixelorama; no unsaved work)
```
Verified 2026-11-06 on Pixelorama v1.2.4 (API 10, Godot 4.7.1 runtime), Godot 4.7.2 build tools: 35/35, 14/14, 10/10, 11/11. Two independent adversarial review rounds: round 1 reproduced name-parameter traversal (`prefix`/`base_name`/palette `name`), symlink escape, a too-broad root and a slow-header stall; round 2 reproduced a dangling-symlink write and a `/health` body stall and found two over-strict regressions (`/` in layer names, non-ASCII `.tres` names). All are fixed and covered by the tests above.

## Not covered
- Other local processes running as the same user can read the token file (same trust boundary as the user).
- Drawing commands are not individually sandboxed; they act on open canvases (undoable in Pixelorama).
- Read commands also expand sparse cels to canvas size in place (content unchanged, not recorded as an undo step).
- The pre-scan is an allow-list of the risky paths found in Pixelorama 1.2.4's loaders (above), not a proof that no other loader path exists; a new Pixelorama version needs the loaders re-read.
- The guard does not cover a session that started without it (`open_guard` `runtime`: files opened at start-up are only re-checked and warned about), extensions installed through Pixelorama's own Extension Explorer (code by design), or another app opening the same files.
