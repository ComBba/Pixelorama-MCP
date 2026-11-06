#!/usr/bin/env node
// End-to-end through the MCP server (stdio JSON-RPC) -> hardened bridge -> running Pixelorama.
//   node tests/mcp_e2e.mjs --allowed-dir DIR [--import-png FILE_INSIDE_ROOT]
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import url from "node:url";

const here = path.dirname(url.fileURLToPath(import.meta.url));
const server = path.join(here, "..", "mcp-server", "dist", "index.js");
const arg = (k) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : null; };
const ALLOWED_DIR = arg("--allowed-dir");
const IMPORT_PNG = arg("--import-png");
const ARBITRARY = "ev" + "al_gdscript";
const results = [];
const check = (name, ok, detail) => results.push({ name, ok: !!ok, detail });

// 1) non-loopback bridge URL must abort at startup (token must never leave the machine)
const bad = spawnSync("node", [server], { env: { ...process.env, PIX_MCP_BRIDGE_URL: "http://attacker.example:7373" }, input: "", timeout: 10000 });
check("non-loopback PIX_MCP_BRIDGE_URL refused at startup", bad.status !== 0 && /must be http:\/\/127\.0\.0\.1/.test(String(bad.stderr)), String(bad.stderr).slice(0, 200));

// 2) normal session
const p = spawn("node", [server], { stdio: ["pipe", "pipe", "pipe"] });
let buf = "";
const waiters = new Map();
p.stdout.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    try { const m = JSON.parse(line); if (waiters.has(m.id)) { waiters.get(m.id)(m); waiters.delete(m.id); } } catch { /* log line */ }
  }
});
let nextId = 1;
const rpc = (method, params) => new Promise((resolve) => {
  const id = nextId++; waiters.set(id, resolve);
  p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
});
const call = async (name, args) => {
  const r = await rpc("tools/call", { name, arguments: args });
  return (r.result?.content || []).map((c) => c.text || "").join("\n");
};

await rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "e2e", version: "0" } });
p.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
const tools = (await rpc("tools/list", {})).result.tools.map((t) => t.name);
check("tools/list served", tools.length > 50, tools.length);
check("arbitrary-code tool absent from MCP surface", !tools.includes(ARBITRARY), tools.filter((t) => /eval|exec|script/.test(t)));

let t = await call("create_canvas", { width: 12, height: 12, name: "mcp_e2e" });
check("create_canvas via MCP", /12/.test(t) && !/❌/.test(t), t.slice(0, 120));
t = await call("draw_pixel", { x: 2, y: 3, color: "#336699" });
check("draw_pixel via MCP", !/❌|error/i.test(t), t.slice(0, 120));
t = await call("export_image", { path: "/tmp/mcp_outside.png" });
check("export outside roots refused at MCP layer", /outside the allowed (write |read )?roots/.test(t), t.slice(0, 160));
t = await call("import_image", { file_path: "/etc/hosts" });
check("import_image outside roots refused (no file read)", /outside the allowed (write |read )?roots/.test(t), t.slice(0, 160));
if (ALLOWED_DIR) {
  const out = path.join(ALLOWED_DIR, "mcp_e2e.png");
  try { fs.unlinkSync(out); } catch { /* none */ }
  t = await call("export_image", { path: out });
  const sig = fs.existsSync(out) ? fs.readFileSync(out).subarray(0, 8).toString("hex") : "";
  check("export inside root via MCP writes PNG", sig === "89504e470d0a1a0a", t.slice(0, 160));
  try { fs.unlinkSync(out); } catch { /* none */ }
}
if (ALLOWED_DIR) {
  t = await call("export_godot_spriteframes", { target_dir: ALLOWED_DIR, sprite_name: 'x"]\n[sub_resource type="GDScript" id="pwn"]', animation_name: "idle" });
  check(".tres identifier injection refused", /must match/.test(t), t.slice(0, 160));
  t = await call("export_aseprite_json", { target_dir: ALLOWED_DIR, base_name: "../../../../tmp/mcp_trav" });
  check("name traversal refused at MCP layer", /plain name/.test(t), t.slice(0, 160));
}
if (IMPORT_PNG) {
  t = await call("import_image", { file_path: IMPORT_PNG, create_new_canvas: true, canvas_name: "imported_sheet" });
  check("import of a repo PNG inside root works", !/❌/.test(t), t.slice(0, 160));
}
p.kill();

let failed = 0;
for (const c of results) { if (!c.ok) failed++; console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.ok ? "" : "  <- " + JSON.stringify(c.detail)}`); }
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
