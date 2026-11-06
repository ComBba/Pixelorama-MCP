/**
 * Hardened fork — shared security helpers for the MCP server process (mirror of security.gd).
 *
 *   ~/.pixelorama-mcp/token        bearer secret sent as X-Pix-Mcp-Token
 *   ~/.pixelorama-mcp/config.json  {"allowed_roots": [write+read], "read_roots": [read-only]}
 * Override the directory with PIX_MCP_CONFIG_DIR (tests). Fail-closed: no roots => no file access.
 * Every path: absolute, no "."/".." or dot-name components, no symlink below the root (realpath),
 * inside a root of the right kind. Name-like params may not contain separators/control chars.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export const TOKEN_HEADER = "X-Pix-Mcp-Token";
export const PATH_KEYS = ["path", "target_dir", "file_path", "dir", "output_path", "output_dir", "export_path"];
export const NAME_KEYS = ["prefix", "base_name", "name", "sprite_name", "animation_name", "tileset_name",
  "canvas_name", "file_name", "filename"];
export const READ_TOOLS = ["open_project", "import_spritesheet", "import_image"];

export function configDir(): string {
  return process.env.PIX_MCP_CONFIG_DIR || path.join(os.homedir(), ".pixelorama-mcp");
}

export function readToken(): string {
  try {
    return fs.readFileSync(path.join(configDir(), "token"), "utf-8").trim();
  } catch {
    return "";
  }
}

const CONTROL = /[\u0000-\u001f\u007f]/;

function badComponent(p: string): boolean {
  return p.split("/").some((c) => c === "." || c === ".." || (c.length > 0 && c.startsWith(".")));
}

/** Resolve symlinks of the longest existing prefix, so a link inside a root cannot escape it. */
function realpathLoose(p: string): string {
  let cur = path.resolve(p);
  const tail: string[] = [];
  while (!fs.existsSync(cur)) {
    const parent = path.dirname(cur);
    if (parent === cur) break;
    tail.unshift(path.basename(cur));
    cur = parent;
  }
  let base = cur;
  try { base = fs.realpathSync(cur); } catch { /* keep resolved */ }
  return path.join(base, ...tail);
}

function loadRoots(key: string): string[] {
  try {
    const data = JSON.parse(fs.readFileSync(path.join(configDir(), "config.json"), "utf-8"));
    const roots = Array.isArray(data[key]) ? data[key] : [];
    return roots.map((r: unknown) => String(r))
      .filter((r: string) => path.isAbsolute(r) && r.length > 1 && !badComponent(r))
      .map((r: string) => realpathLoose(r));
  } catch {
    return [];
  }
}

export function allowedRoots(forWrite = true): string[] {
  return forWrite ? loadRoots("allowed_roots") : [...loadRoots("allowed_roots"), ...loadRoots("read_roots")];
}

/** Throws unless `p` is a safe absolute path inside a root of the right kind (symlinks resolved). */
export function assertAllowedPath(p: string, label = "path", forWrite = true): string {
  if (typeof p !== "string" || p.length === 0) throw new Error(`Missing ${label}`);
  if (!path.isAbsolute(p) || CONTROL.test(p) || p.includes("://") || p.includes("\\")) {
    throw new Error(`${label} must be an absolute local path`);
  }
  if (badComponent(p)) throw new Error(`${label} may not contain '.', '..' or hidden (dot) components`);
  const roots = allowedRoots(forWrite);
  // realpath of the target must stay inside the realpath of a root (defeats symlinks below the root)
  const resolved = realpathLoose(p);
  const ok = roots.some((r) => resolved === r || resolved.startsWith(r + path.sep));
  if (!ok) {
    throw new Error(
      `${label} '${p}' is outside the allowed ${forWrite ? "write" : "read"} roots (${roots.join(", ") || "none configured"}). ` +
        `Edit ${path.join(configDir(), "config.json")} to allow a directory.`
    );
  }
  return resolved;
}

export function assertSafeName(v: unknown, label: string): void {
  const s = String(v);
  if (s.includes("/") || s.includes("\\") || s === "." || s === ".." || CONTROL.test(s)) {
    throw new Error(`${label} must be a plain name (no path separators or control characters)`);
  }
}

/** Validate every path-like and name-like parameter before it is sent to the bridge. */
export function assertParamsAllowed(tool: string, params: Record<string, unknown>): void {
  const forWrite = !READ_TOOLS.includes(tool);
  for (const key of PATH_KEYS) {
    const v = params[key];
    if (typeof v === "string" && v.length > 0) assertAllowedPath(v, key, forWrite);
  }
  for (const key of NAME_KEYS) {
    if (key in params && params[key] !== undefined && params[key] !== null) assertSafeName(params[key], key);
  }
}

/** Godot resource identifiers written into .tres files: strict allow-list (no quotes/newlines). */
export function assertResourceIdent(v: string, label: string): void {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(v)) throw new Error(`${label} must match [A-Za-z0-9_-]{1,64}`);
}

/** Only loopback bridge URLs are accepted; anything else would leak the token. */
export function loopbackUrl(raw: string): string {
  const u = new URL(raw);
  if (u.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(u.hostname)) {
    throw new Error(`PIX_MCP_BRIDGE_URL must be http://127.0.0.1:<port> or http://localhost:<port> (got ${raw})`);
  }
  return `${u.protocol}//${u.host}`;
}
