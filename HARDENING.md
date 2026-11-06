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
| Project files | `open_project` passed any file to Pixelorama's loader | pre-scan of `.pxo` (see Not covered) |
| Pixelorama 1.2.4 compatibility | cels assumed canvas-sized; 1.2.4 cels are sparse (used rect + `offset`, empty = 1x1) so draws/reads silently did nothing | `_norm(cel)` expands a cel to canvas size at offset 0 before use (content unchanged, offset/size are in undo data) |

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
```
Verified 2026-11-06 on Pixelorama v1.2.4 (API 10), Godot 4.7.2 build tools: 35/35 and 14/14. Two independent adversarial review rounds: round 1 reproduced name-parameter traversal (`prefix`/`base_name`/palette `name`), symlink escape, a too-broad root and a slow-header stall; round 2 reproduced a dangling-symlink write and a `/health` body stall and found two over-strict regressions (`/` in layer names, non-ASCII `.tres` names). All are fixed and covered by the tests above.

## Not covered
- Other local processes running as the same user can read the token file (same trust boundary as the user).
- Drawing commands are not individually sandboxed; they act on open canvases (undoable in Pixelorama).
- Read commands also expand sparse cels to canvas size in place (content unchanged, not recorded as an undo step).
- `open_project` pre-scans the file before Pixelorama's loader sees it: `.pxo` extension and zip format only (legacy v0 loader refused), no `scene/` entries (Pixelorama 1.2.4 `load()`s embedded 3D-layer scenes behind a substring-only script guard), cel `image_size` / tileset `tile_size` must be plain integer pairs (they go through `str_to_var`), and no `Object(` literal anywhere in `data.json`. Whether the upstream loader is actually exploitable was not tested; the risky paths are refused instead (`tests/pxo_test.py`, 8 checks). Opening hostile `.pxo` files through Pixelorama's own GUI is outside this fork.
