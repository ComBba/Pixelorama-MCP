## pix-MCP Bridge — Main Extension Entry Point (HARDENED FORK)
## Hardening (ComBba/Pixelorama-MCP, branch `hardened`): token auth, browser/DNS-rebinding refusal
## (Origin / Sec-Fetch-* / Host checks), JSON-only, no CORS, request size caps, eval_gdscript removed,
## file paths restricted to ~/.pixelorama-mcp/config.json allowed_roots (see security.gd).
## Uses a dedicated background Thread for instant TCP socket reception (even when minimized)
## and safely dispatches all Pixelorama commands to the Main Thread via call_deferred + Semaphore
## to prevent any OpenGL / SceneTree threading collisions or crashes.
extends Node

const PORT: int = 7373
const MAX_REQUEST_SIZE: int = 4194304  # 4 MB max request body
const MAX_HEADER_SIZE: int = 16384
const ALLOWED_HOSTS := ["127.0.0.1:7373", "localhost:7373"]

var _server: TCPServer = TCPServer.new()
var _thread: Thread = Thread.new()
var _is_running: bool = false
var _api: Node = null
var _command_handler: RefCounted = null
var _security: RefCounted = null

const LOG_TAG: String = "[pix-MCP] "

class PendingRequest extends RefCounted:
	var tool_name: String = ""
	var params: Dictionary = {}
	var response: Dictionary = {}
	var semaphore: Semaphore = Semaphore.new()
	var timed_out: bool = false


func _enter_tree() -> void:
	# Prevent Godot from deep-sleeping when unfocused/minimized
	OS.low_processor_usage_mode = false
	OS.low_processor_usage_mode_sleep_usec = 1000

	_api = get_node_or_null("/root/ExtensionsApi")
	if _api == null:
		push_error(LOG_TAG + "ExtensionsApi not found! Is this running inside Pixelorama?")
		return

	_security = preload("security.gd").new()
	_security.load_config()
	if _security.token.is_empty():
		push_error(LOG_TAG + "No auth token available; refusing to start the bridge.")
		return
	_command_handler = preload("command_handler.gd").new()
	_command_handler.initialize(_api)
	_command_handler.set_security(_security)
	print(LOG_TAG + "Auth token file: %s/token · allowed roots: %s" % [_security.config_dir, ", ".join(_security.allowed_roots)])

	var err := _server.listen(PORT, "127.0.0.1")
	if err != OK:
		push_error(LOG_TAG + "Failed to start HTTP server on port %d: %s" % [PORT, error_string(err)])
		return

	print(LOG_TAG + "HTTP server listening on 127.0.0.1:%d" % PORT)
	print(LOG_TAG + "Pixelorama version: %s" % _api.general.get_pixelorama_version())
	print(LOG_TAG + "ExtensionsApi version: %d" % _api.get_api_version())

	_is_running = true
	_thread.start(_server_worker_loop)
	print(LOG_TAG + "Thread-safe background listener active")


func _server_worker_loop() -> void:
	while _is_running:
		if not _server.is_listening():
			OS.delay_msec(20)
			continue

		if _server.is_connection_available():
			var peer := _server.take_connection()
			if peer:
				_handle_peer_connection(peer)
		else:
			OS.delay_msec(2)


func _handle_peer_connection(peer: StreamPeerTCP) -> void:
	var buffer := PackedByteArray()
	var headers_parsed := false
	var content_length := 0
	var header_end_index := -1
	var start_time := Time.get_ticks_msec()
	const TIMEOUT_MS := 120000

	while _is_running and peer.get_status() == StreamPeerTCP.STATUS_CONNECTED:
		peer.poll()
		var available := peer.get_available_bytes()
		if available > 0:
			var data := peer.get_data(mini(available, MAX_REQUEST_SIZE))
			if data[0] == OK:
				buffer.append_array(data[1])
		if buffer.size() > MAX_HEADER_SIZE + MAX_REQUEST_SIZE:
			_send_response(peer, 413, {"error": "Request too large"})
			return

		if not headers_parsed:
			var header_end := _find_header_end(buffer)
			if header_end == -1 and buffer.size() > MAX_HEADER_SIZE:
				_send_response(peer, 431, {"error": "Headers too large"})
				return
			if header_end != -1:
				headers_parsed = true
				header_end_index = header_end + 4

				var header_bytes := buffer.slice(0, header_end)
				var header_str := header_bytes.get_string_from_utf8()
				var lines := header_str.split("\r\n")
				for line in lines:
					if line.to_lower().begins_with("content-length:"):
						content_length = int(line.split(":")[1].strip_edges())
						break
				if content_length < 0 or content_length > MAX_REQUEST_SIZE:
					_send_response(peer, 413, {"error": "Request body too large"})
					return

		if headers_parsed:
			var body_received := buffer.size() - header_end_index
			if body_received >= content_length:
				_process_http_request(peer, buffer, header_end_index, content_length)
				return

		if Time.get_ticks_msec() - start_time > TIMEOUT_MS:
			push_warning(LOG_TAG + "Client request timed out")
			peer.disconnect_from_host()
			return

		OS.delay_msec(1)

	if peer.get_status() == StreamPeerTCP.STATUS_CONNECTED:
		peer.disconnect_from_host()


func _find_header_end(buf: PackedByteArray) -> int:
	var sz := buf.size()
	if sz < 4:
		return -1
	for i in range(sz - 3):
		if buf[i] == 13 and buf[i + 1] == 10 and buf[i + 2] == 13 and buf[i + 3] == 10:
			return i
	return -1


func _parse_headers(header_str: String) -> Dictionary:
	var headers := {}
	var lines := header_str.split("\r\n")
	for i in range(1, lines.size()):
		var idx := lines[i].find(":")
		if idx > 0:
			headers[lines[i].substr(0, idx).strip_edges().to_lower()] = lines[i].substr(idx + 1).strip_edges()
	return headers


## Returns [status, error] for a request that must be refused, or [] when it may proceed.
func _security_gate(method: String, path: String, headers: Dictionary) -> Array:
	# Browsers always attach Origin and/or Sec-Fetch-* to cross-site and fetch() requests: a real MCP
	# client (Node) never does. Refusing them blocks drive-by web pages (CSRF / simple-request POSTs).
	if headers.has("origin") or headers.has("referer"):
		return [403, "Browser-originated requests are refused"]
	for k in headers.keys():
		if str(k).begins_with("sec-fetch-"):
			return [403, "Browser-originated requests are refused"]
	# DNS-rebinding defence: the Host must be the loopback name we bind to.
	if not ALLOWED_HOSTS.has(str(headers.get("host", "")).to_lower()):
		return [403, "Invalid Host header"]
	if method == "GET" and path == "/health":
		return []
	if not _security.constant_time_equals(str(headers.get(_security.TOKEN_HEADER, "")), _security.token):
		return [401, "Missing or invalid %s header" % _security.TOKEN_HEADER]
	if method == "POST" and not str(headers.get("content-type", "")).to_lower().begins_with("application/json"):
		return [415, "Content-Type must be application/json"]
	return []


func _process_http_request(peer: StreamPeerTCP, buffer: PackedByteArray, header_end: int, content_length: int) -> void:
	var header_bytes := buffer.slice(0, header_end)
	var header_str := header_bytes.get_string_from_utf8()
	var first_line := header_str.split("\r\n")[0]
	var parts := first_line.split(" ")
	var method: String = parts[0] if parts.size() > 0 else ""
	var path: String = parts[1] if parts.size() > 1 else ""
	var headers := _parse_headers(header_str)

	var refused := _security_gate(method, path, headers)
	if refused.size() > 0:
		push_warning(LOG_TAG + "Refused %s %s: %s" % [method, path, refused[1]])
		_send_response(peer, refused[0], {"success": false, "error": refused[1]})
		return

	var body := ""
	if header_end < buffer.size():
		var body_len: int = content_length if content_length > 0 else (buffer.size() - header_end)
		var body_bytes := buffer.slice(header_end, header_end + body_len)
		body = body_bytes.get_string_from_utf8()

	if method == "GET" and path == "/health":
		_send_response(peer, 200, {
			"status": "ok",
			"server": "pix-mcp-bridge-hardened",
			"version": "0.2.1-hardened.1",
			"pixelorama_version": _api.general.get_pixelorama_version() if _api else "unknown",
			"api_version": _api.get_api_version() if _api else -1
		})
	elif method == "POST" and path == "/command":
		var result := _dispatch_command_to_main_thread(body)
		var status_code := 200
		if not result.get("success", false):
			status_code = 504 if str(result.get("error", "")).find("timed out") != -1 else 400
		_send_response(peer, status_code, result)
	elif method == "GET" and path == "/tools":
		_send_response(peer, 200, {"tools": _command_handler.get_available_tools() if _command_handler else []})
	else:
		_send_response(peer, 404 if method in ["GET", "POST"] else 405, {"error": "Not found", "path": path, "method": method})


func _send_response(peer: StreamPeerTCP, status_code: int, payload: Dictionary) -> void:
	# No Access-Control-* headers: cross-origin browser reads stay blocked by the same-origin policy.
	var body_bytes: PackedByteArray = JSON.stringify(payload).to_utf8_buffer()
	var response_header := "HTTP/1.1 %d %s\r\n" % [status_code, _status_text(status_code)]
	response_header += "Content-Type: application/json; charset=utf-8\r\n"
	response_header += "Content-Length: %d\r\n" % body_bytes.size()
	response_header += "X-Content-Type-Options: nosniff\r\n"
	response_header += "Connection: close\r\n"
	response_header += "\r\n"
	var full_response := response_header.to_utf8_buffer()
	full_response.append_array(body_bytes)
	peer.put_data(full_response)
	peer.disconnect_from_host()


func _dispatch_command_to_main_thread(body: String) -> Dictionary:
	if _command_handler == null:
		return {"success": false, "error": "Command handler not initialized"}

	var json := JSON.new()
	var err := json.parse(body)
	if err != OK:
		return {"success": false, "error": "Invalid JSON: %s" % json.get_error_message()}

	var data: Variant = json.data
	if not data is Dictionary:
		return {"success": false, "error": "Request body must be a JSON object"}

	var tool_name: String = data.get("tool", "")
	var params: Dictionary = data.get("params", {})

	if tool_name.is_empty():
		return {"success": false, "error": "Missing 'tool' field in request"}

	var req := PendingRequest.new()
	req.tool_name = tool_name
	req.params = params

	call_deferred("_execute_on_main_thread", req)

	const EXEC_TIMEOUT_MS := 60000
	var start_exec := Time.get_ticks_msec()
	var completed := false
	while _is_running:
		if req.semaphore.try_wait():
			completed = true
			break
		if Time.get_ticks_msec() - start_exec > EXEC_TIMEOUT_MS:
			break
		OS.delay_msec(2)

	if not completed:
		req.timed_out = true
		push_warning(LOG_TAG + "Execution timed out for tool '%s' after %d ms" % [tool_name, EXEC_TIMEOUT_MS])
		return {
			"success": false,
			"error": "Command execution timed out on main thread after %d ms" % EXEC_TIMEOUT_MS
		}

	return req.response


func _execute_on_main_thread(req: PendingRequest) -> void:
	if req.timed_out:
		req.semaphore.post()
		return

	if _command_handler != null:
		req.response = _command_handler.execute(req.tool_name, req.params)
	else:
		req.response = {"success": false, "error": "Command handler not initialized"}
	req.semaphore.post()


func _status_text(code: int) -> String:
	match code:
		200: return "OK"
		204: return "No Content"
		400: return "Bad Request"
		401: return "Unauthorized"
		403: return "Forbidden"
		404: return "Not Found"
		405: return "Method Not Allowed"
		413: return "Payload Too Large"
		415: return "Unsupported Media Type"
		431: return "Request Header Fields Too Large"
		500: return "Internal Server Error"
		504: return "Gateway Timeout"
	return "Unknown"


func _exit_tree() -> void:
	_is_running = false

	if _server.is_listening():
		_server.stop()

	if _thread.is_started():
		_thread.wait_to_finish()

	OS.low_processor_usage_mode = true
	print(LOG_TAG + "HTTP server and background thread stopped")
