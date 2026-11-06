## pix-MCP hardened fork — shared security helpers for the bridge.
## Config lives OUTSIDE Pixelorama's data dir so the MCP server (another process) can read it:
##   ~/.pixelorama-mcp/token        random 64-hex secret, created on first start, mode 0600
##   ~/.pixelorama-mcp/config.json  {"allowed_roots": ["/abs/dir", ...]}  — file paths outside are refused
## Fail-closed: no config / no roots => every path-taking command is refused.
extends RefCounted

const TOKEN_HEADER := "x-pix-mcp-token"
const PATH_KEYS := ["path", "target_dir", "file_path", "dir", "output_path", "output_dir"]
const MODE_DIR := 448     # 0700
const MODE_FILE := 384    # 0600

var token: String = ""
var allowed_roots: PackedStringArray = PackedStringArray()
var config_dir: String = ""


func load_config() -> void:
	var home := OS.get_environment("HOME")
	if home.is_empty():
		home = OS.get_environment("USERPROFILE")
	config_dir = home.path_join(".pixelorama-mcp")
	if not DirAccess.dir_exists_absolute(config_dir):
		DirAccess.make_dir_recursive_absolute(config_dir)
	FileAccess.set_unix_permissions(config_dir, MODE_DIR)
	token = _load_or_create_token(config_dir.path_join("token"))
	allowed_roots = _load_roots(config_dir.path_join("config.json"))


func _load_or_create_token(path: String) -> String:
	if FileAccess.file_exists(path):
		var existing := FileAccess.get_file_as_string(path).strip_edges()
		if existing.length() >= 32:
			FileAccess.set_unix_permissions(path, MODE_FILE)
			return existing
	var fresh := Crypto.new().generate_random_bytes(32).hex_encode()
	var f := FileAccess.open(path, FileAccess.WRITE)
	if f == null:
		push_error("[pix-MCP] cannot write token file: " + path)
		return ""
	f.store_string(fresh)
	f.close()
	FileAccess.set_unix_permissions(path, MODE_FILE)
	return fresh


func _load_roots(path: String) -> PackedStringArray:
	var roots := PackedStringArray()
	if not FileAccess.file_exists(path):
		return roots
	var data: Variant = JSON.parse_string(FileAccess.get_file_as_string(path))
	if not data is Dictionary:
		return roots
	for r in data.get("allowed_roots", []):
		var s := normalize(str(r))
		if s.begins_with("/") and s.length() > 1:
			roots.append(s)
	return roots


static func normalize(p: String) -> String:
	var s := p.strip_edges().simplify_path()
	while s.length() > 1 and s.ends_with("/"):
		s = s.substr(0, s.length() - 1)
	return s


func is_path_allowed(p: String) -> bool:
	if p.is_empty() or p.begins_with("~") or p.find("://") != -1:
		return false
	if not p.begins_with("/"):
		return false
	var s := normalize(p)
	if s.find("/../") != -1 or s.ends_with("/.."):
		return false
	for root in allowed_roots:
		if s == root or s.begins_with(root + "/"):
			return true
	return false


## Returns "" when OK, otherwise an error message naming the offending parameter.
func check_params(params: Dictionary) -> String:
	for key in PATH_KEYS:
		if params.has(key):
			var v := str(params[key])
			if v.is_empty():
				continue
			if not is_path_allowed(v):
				return "Path for '%s' is outside the allowed roots (%s). Configure %s/config.json." % [
					key, ", ".join(allowed_roots) if allowed_roots.size() > 0 else "none configured", config_dir]
	return ""


static func constant_time_equals(a: String, b: String) -> bool:
	var ab := a.to_utf8_buffer()
	var bb := b.to_utf8_buffer()
	if ab.size() != bb.size() or ab.is_empty():
		return false
	var diff := 0
	for i in ab.size():
		diff |= ab[i] ^ bb[i]
	return diff == 0
