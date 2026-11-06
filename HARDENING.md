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
| Browser / CSRF | CORS `*`, `OPTIONS` answered, any Content-Type | requests carrying `Origin`, `Referer` or any `Sec-Fetch-*` are refused (403); no `Access-Control-*` headers; `OPTIONS` 405; `POST` must be `application/json` (415) |
| DNS rebinding | Host not checked | `Host` must be `127.0.0.1:7373` or `localhost:7373` (403) |
| File access | any absolute path for save/open/export/import | every `path`/`target_dir`/… parameter must be inside `allowed_roots` of `~/.pixelorama-mcp/config.json` (fail-closed when absent); checked in the bridge **and** in the MCP server (symlink-resolved) |
| Request size | body length unchecked | headers ≤ 16 KB, body ≤ 4 MB (413/431) |
| MCP client | `fetch` to `PIX_MCP_BRIDGE_URL` (any host) | `node:http`, loopback URLs only (startup error otherwise), token attached |
| Shipped binaries/scripts | prebuilt `PixMcpBridge.pck`, 6 MB `Pixelorama.pck`, `start_pixelorama.sh` (`kill -9`, `rm -rf` on author paths), ad-hoc test scripts | removed; `pack.gd` builds `PixMcpBridge.pck` from source only and copies nothing |
| Pixelorama 1.2.4 compatibility | cels assumed canvas-sized; 1.2.4 cels are sparse (used rect + `offset`, empty = 1x1) so draws/reads silently did nothing | `_norm(cel)` expands a cel to canvas size at offset 0 before use (content unchanged, offset/size are in undo data) |

## Build and install (macOS)
```bash
cd mcp-server && npm ci --ignore-scripts && npm run build && cd ..
# GIF exporter shaders from the official Pixelorama source (MIT), tag matching your Pixelorama:
#   pixelorama-source/addons/gdgifexporter/lookup_similar.gdshader, lookup_color.gdshader
godot --headless --script pack.gd          # -> PixMcpBridge.pck (reproducible: same sources -> same SHA-256)
scripts/dev_reload.sh                      # install into Pixelorama, restart safely, wait for the bridge
```
Create `~/.pixelorama-mcp/config.json` (mode 0600) with `{"allowed_roots": ["/abs/project/dir"]}`.

## Tests (need a running Pixelorama with the extension)
```bash
node tests/security_test.mjs --allowed-dir <dir inside a root>   # 19 checks: 15 attack scenarios + functional
node tests/mcp_e2e.mjs --allowed-dir <dir> --import-png <png inside a root>   # 9 checks through MCP stdio
```
Verified 2026-11-06 on Pixelorama v1.2.4 (API 10), Godot 4.7.2 build tools: 19/19 and 9/9.

## Not covered
- Other local processes running as the same user can read the token file (same trust boundary as the user).
- Drawing commands are not individually sandboxed; they act on open canvases (undoable in Pixelorama).
