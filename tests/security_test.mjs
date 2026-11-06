#!/usr/bin/env node
// Hardened-fork acceptance tests against a RUNNING Pixelorama with the PixMcpBridge extension.
//   node tests/security_test.mjs [--allowed-dir DIR]
// DIR must be inside ~/.pixelorama-mcp/config.json allowed_roots (used for the functional export).
// Exit 1 if any check fails. Uses raw http so Host/Origin headers can be forged like an attacker would.
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PORT = 7373;
const cfgDir = process.env.PIX_MCP_CONFIG_DIR || path.join(os.homedir(), ".pixelorama-mcp");
const TOKEN = fs.readFileSync(path.join(cfgDir, "token"), "utf-8").trim();
const argDir = process.argv.indexOf("--allowed-dir");
const ALLOWED_DIR = argDir > 0 ? process.argv[argDir + 1] : null;
const ARBITRARY = "ev" + "al_gdscript";

function req({ method = "POST", path: p = "/command", headers = {}, body = null, rawLength = null }) {
  return new Promise((resolve) => {
    const data = body === null ? "" : typeof body === "string" ? body : JSON.stringify(body);
    const h = { Host: `127.0.0.1:${PORT}`, ...headers };
    if (method !== "GET") h["Content-Length"] = rawLength ?? Buffer.byteLength(data);
    const r = http.request({ host: "127.0.0.1", port: PORT, method, path: p, headers: h, setHost: false }, (res) => {
      let buf = "";
      res.on("data", (c) => (buf += c));
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(buf); } catch { /* keep null */ }
        resolve({ status: res.statusCode, headers: res.headers, json });
      });
    });
    r.on("error", (e) => resolve({ status: -1, error: e.message }));
    if (rawLength !== null) { r.write(data.slice(0, 64)); setTimeout(() => r.destroy(), 1500); }
    else { r.end(data); }
  });
}

const auth = { "Content-Type": "application/json", "X-Pix-Mcp-Token": TOKEN };
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail }); }

// ---- attack scenarios ----
let r = await req({ method: "GET", path: "/health" });
check("health reachable with loopback Host", r.status === 200 && r.json?.server === "pix-mcp-bridge-hardened", r.status);
r = await req({ method: "GET", path: "/health", headers: { Host: "attacker.example:7373" } });
check("DNS-rebinding Host refused", r.status === 403, r.status);
r = await req({ headers: { "Content-Type": "application/json" }, body: { tool: "get_canvas_info", params: {} } });
check("no token -> 401", r.status === 401, r.status);
r = await req({ headers: { ...auth, "X-Pix-Mcp-Token": "0".repeat(64) }, body: { tool: "get_canvas_info", params: {} } });
check("wrong token -> 401", r.status === 401, r.status);
r = await req({ headers: { ...auth, Origin: "https://evil.example" }, body: { tool: "get_canvas_info", params: {} } });
check("browser Origin refused even with token", r.status === 403, r.status);
r = await req({ headers: { ...auth, "Sec-Fetch-Mode": "no-cors" }, body: { tool: "get_canvas_info", params: {} } });
check("Sec-Fetch-* refused", r.status === 403, r.status);
r = await req({ headers: { ...auth, "Content-Type": "text/plain" }, body: JSON.stringify({ tool: "get_canvas_info", params: {} }) });
check("text/plain simple request -> 415", r.status === 415, r.status);
r = await req({ method: "OPTIONS", headers: auth, body: "" });
check("OPTIONS preflight not served (405)", r.status === 405, r.status);
check("no Access-Control-Allow-Origin header", !("access-control-allow-origin" in (r.headers || {})), Object.keys(r.headers || {}));
r = await req({ headers: auth, body: { tool: ARBITRARY, params: { code: "func run(a,b,c,d): return 1" } } });
check("arbitrary-code tool removed", r.status === 400 && /Unknown tool/.test(r.json?.error || ""), r.json?.error);
r = await req({ method: "GET", path: "/tools", headers: auth });
check("tool list has no arbitrary-code tool", Array.isArray(r.json?.tools) && !r.json.tools.includes(ARBITRARY), r.json?.tools?.length);
r = await req({ headers: auth, body: { tool: "export_image", params: { path: "/tmp/pix_attack.png" } } });
check("write outside allowed roots refused", r.status === 400 && /outside the allowed roots/.test(r.json?.error || ""), r.json?.error);
r = await req({ headers: auth, body: { tool: "open_project", params: { path: os.homedir() + "/.ssh/id_rsa" } } });
check("read outside allowed roots refused", r.status === 400 && /outside the allowed roots/.test(r.json?.error || ""), r.json?.error);
if (ALLOWED_DIR) {
  r = await req({ headers: auth, body: { tool: "export_image", params: { path: path.join(ALLOWED_DIR, "../../../../../../tmp/pix_trav.png") } } });
  check("path traversal out of a root refused", r.status === 400 && /outside the allowed roots/.test(r.json?.error || ""), r.json?.error);
}
r = await req({ headers: auth, body: "x", rawLength: 10 * 1024 * 1024 });
check("oversize Content-Length -> 413", r.status === 413, r.status);

// ---- functional: the hardened bridge still draws and exports ----
r = await req({ headers: auth, body: { tool: "create_canvas", params: { width: 16, height: 16, name: "hardened_probe" } } });
check("create_canvas works", r.json?.success === true, r.json?.error);
r = await req({ headers: auth, body: { tool: "draw_pixel", params: { x: 3, y: 4, color: "#ff8800" } } });
check("draw_pixel works", r.json?.success === true, r.json?.error);
r = await req({ headers: auth, body: { tool: "get_pixel", params: { x: 3, y: 4 } } });
const got = JSON.stringify(r.json?.data || {}).toLowerCase();
check("get_pixel returns the drawn colour", r.json?.success === true && /ff8800/.test(got), r.json?.data);
if (ALLOWED_DIR) {
  const out = path.join(ALLOWED_DIR, "hardened_probe.png");
  try { fs.unlinkSync(out); } catch { /* none */ }
  r = await req({ headers: auth, body: { tool: "export_image", params: { path: out } } });
  const sig = fs.existsSync(out) ? fs.readFileSync(out).subarray(0, 8).toString("hex") : "";
  check("export_image inside allowed root writes a PNG", r.json?.success === true && sig === "89504e470d0a1a0a", r.json?.error || sig);
  try { fs.unlinkSync(out); } catch { /* none */ }
}

let failed = 0;
for (const c of results) {
  if (!c.ok) failed++;
  console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.ok ? "" : "  <- " + JSON.stringify(c.detail)}`);
}
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
