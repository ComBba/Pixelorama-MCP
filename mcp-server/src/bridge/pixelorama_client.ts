/**
 * Pixelorama Bridge Client (hardened fork)
 *
 * Sends commands to the PixMcpBridge extension's loopback HTTP server as POST /command.
 * Uses node:http instead of fetch(): undici's fetch always adds `Sec-Fetch-Mode: cors`, and the
 * hardened bridge rejects every Sec-Fetch-* / Origin request as browser-originated.
 */
import * as http from "http";
import { TOKEN_HEADER, readToken, assertParamsAllowed, loopbackUrl } from "../utils/security.js";

// Loopback only (the token must never leave the machine). Throws at startup otherwise.
const BRIDGE = new URL(loopbackUrl(process.env.PIX_MCP_BRIDGE_URL || "http://127.0.0.1:7373"));
const DEFAULT_TIMEOUT_MS = parseInt(process.env.PIX_MCP_TIMEOUT_MS || "120000", 10) || 120_000;

export interface BridgeResponse {
  success: boolean;
  data?: Record<string, any>;
  error?: string;
}

// FIFO queue to serialize commands and prevent race conditions when LLMs fire parallel tool calls
let commandQueue: Promise<unknown> = Promise.resolve();

function request(method: "GET" | "POST", pathname: string, body: string | null, headers: Record<string, string>,
                 timeoutMs: number): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: BRIDGE.hostname, port: Number(BRIDGE.port || 80), method, path: pathname,
        headers: { ...headers, ...(body !== null ? { "Content-Length": Buffer.byteLength(body).toString() } : {}) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf-8");
          try { resolve({ status: res.statusCode || 0, json: JSON.parse(text) }); }
          catch { resolve({ status: res.statusCode || 0, json: { success: false, error: text.slice(0, 200) } }); }
        });
      }
    );
    req.setTimeout(timeoutMs, () => req.destroy(Object.assign(new Error("timeout"), { name: "AbortError" })));
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

/**
 * Send a command to the Pixelorama bridge plugin.
 * Serialized in strict order to avoid concurrent mutation races.
 */
export async function sendCommand(
  tool: string,
  params: Record<string, unknown> = {},
  timeoutMs?: number
): Promise<BridgeResponse> {
  return new Promise<BridgeResponse>((resolve) => {
    commandQueue = commandQueue
      .then(async () => resolve(await _executeHttpCommand(tool, params, timeoutMs)))
      .catch((err) => resolve({ success: false, error: err instanceof Error ? err.message : String(err) }));
  });
}

async function _executeHttpCommand(
  tool: string,
  params: Record<string, unknown>,
  timeoutMs?: number
): Promise<BridgeResponse> {
  const effectiveTimeout = timeoutMs ?? DEFAULT_TIMEOUT_MS;
  try {
    assertParamsAllowed(params);
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : String(err) };
  }
  const token = readToken();
  if (!token) {
    return { success: false, error: "No bridge token found (~/.pixelorama-mcp/token). Start Pixelorama with the hardened PixMcpBridge extension first." };
  }
  try {
    const { json } = await request("POST", "/command", JSON.stringify({ tool, params }),
      { "Content-Type": "application/json", [TOKEN_HEADER]: token }, effectiveTimeout);
    return json as BridgeResponse;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      return {
        success: false,
        error: `Request timed out after ${effectiveTimeout}ms while executing '${tool}'. NOTE: The operation may have completed or still be processing in Pixelorama (changes may already have been committed). Do not blind-retry without inspecting state with get_pixels or get_canvas_image. Increase PIX_MCP_TIMEOUT_MS if running heavy operations.`,
      };
    }
    const message = error instanceof Error ? error.message : "Unknown error";
    if (message.includes("ECONNREFUSED")) {
      return { success: false, error: `Cannot connect to Pixelorama bridge at ${BRIDGE.origin}. Make sure Pixelorama is running with the hardened PixMcpBridge.pck extension enabled.` };
    }
    return { success: false, error: message };
  }
}

/**
 * Check if the Pixelorama bridge is reachable (unauthenticated /health).
 */
export async function checkHealth(): Promise<BridgeResponse> {
  try {
    const { json } = await request("GET", "/health", null, {}, 3000);
    return json as BridgeResponse;
  } catch {
    return { success: false, error: `Pixelorama bridge not reachable at ${BRIDGE.origin}` };
  }
}
