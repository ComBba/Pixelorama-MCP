/**
 * Hardened fork — shared security helpers for the MCP server process.
 *
 * Reads the same files the Pixelorama bridge creates/uses:
 *   ~/.pixelorama-mcp/token        bearer secret sent as X-Pix-Mcp-Token
 *   ~/.pixelorama-mcp/config.json  {"allowed_roots": ["/abs/dir", ...]}
 * Override the directory with PIX_MCP_CONFIG_DIR (tests). Fail-closed: no roots => no file access.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export const TOKEN_HEADER = "X-Pix-Mcp-Token";
export const PATH_KEYS = ["path", "target_dir", "file_path", "dir", "output_path", "output_dir", "export_path"];

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
  try {
    base = fs.realpathSync(cur);
  } catch {
    /* keep resolved */
  }
  return path.join(base, ...tail);
}

export function allowedRoots(): string[] {
  try {
    const data = JSON.parse(fs.readFileSync(path.join(configDir(), "config.json"), "utf-8"));
    const roots = Array.isArray(data.allowed_roots) ? data.allowed_roots : [];
    return roots
      .map((r: unknown) => String(r))
      .filter((r: string) => path.isAbsolute(r) && r.length > 1)
      .map((r: string) => realpathLoose(r));
  } catch {
    return [];
  }
}

/** Throws when `p` is not an absolute path inside an allowed root (after symlink resolution). */
export function assertAllowedPath(p: string, label = "path"): string {
  if (typeof p !== "string" || p.length === 0) throw new Error(`Missing ${label}`);
  if (!path.isAbsolute(p) || p.includes("\0") || p.includes("://")) {
    throw new Error(`${label} must be an absolute local path`);
  }
  const resolved = realpathLoose(p);
  const roots = allowedRoots();
  const ok = roots.some((r) => resolved === r || resolved.startsWith(r + path.sep));
  if (!ok) {
    throw new Error(
      `${label} '${p}' is outside the allowed roots (${roots.join(", ") || "none configured"}). ` +
        `Edit ${path.join(configDir(), "config.json")} to allow a directory.`
    );
  }
  return resolved;
}

/** Validate every path-like parameter before it is sent to the bridge. */
export function assertParamsAllowed(params: Record<string, unknown>): void {
  for (const key of PATH_KEYS) {
    const v = params[key];
    if (typeof v === "string" && v.length > 0) assertAllowedPath(v, key);
  }
}

/** Only loopback bridge URLs are accepted; anything else would leak the token. */
export function loopbackUrl(raw: string): string {
  const u = new URL(raw);
  if (u.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(u.hostname)) {
    throw new Error(`PIX_MCP_BRIDGE_URL must be http://127.0.0.1:<port> or http://localhost:<port> (got ${raw})`);
  }
  return `${u.protocol}//${u.host}`;
}
