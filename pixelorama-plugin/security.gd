## pix-MCP hardened fork — shared security helpers for the bridge.
## Config lives OUTSIDE Pixelorama's data dir so the MCP server (another process) can read it:
##   ~/.pixelorama-mcp/token        random 64-hex secret, created on first start, mode 0600
##   ~/.pixelorama-mcp/config.json  {"allowed_roots": [...write+read...], "read_roots": [...read-only...]}
## Fail-closed: no config / no roots => every path-taking command is refused.
## Rules for every path: absolute; no "." / ".." components; no component starting with "." (blocks
## .git, .claude, .ssh, dotfiles); no symlink anywhere below the root; inside a root of the right kind.
## Name-like parameters that become file names (prefix, base_name, palette name, ...) may not contain
## separators or control characters (they were a traversal bypass: review 2026-11-06).
extends RefCounted

const TOKEN_HEADER := "x-pix-mcp-token"
const PATH_KEYS := ["path", "target_dir", "file_path", "dir", "output_path", "output_dir"]
const NAME_KEYS := ["prefix", "base_name", "sprite_name", "animation_name", "tileset_name",
	"file_name", "filename"]
## `name` only becomes a file name for these tools (layer/canvas names may legitimately contain "/").
const FILE_NAME_TOOLS := {"create_palette": ["name"], "delete_palette": ["name"], "switch_palette": ["name"]}
## Tools whose path parameters are only READ (may use read_roots); everything else writes.
const READ_TOOLS := ["open_project", "import_spritesheet", "import_image"]
const MODE_DIR := 448     # 0700
const MODE_FILE := 384    # 0600

var token: String = ""
var allowed_roots: PackedStringArray = PackedStringArray()   # write + read
var read_roots: PackedStringArray = PackedStringArray()      # read only
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
	var cfg_path := config_dir.path_join("config.json")
	allowed_roots = _load_roots(cfg_path, "allowed_roots")
	read_roots = _load_roots(cfg_path, "read_roots")


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


func _load_roots(path: String, key: String) -> PackedStringArray:
	var roots := PackedStringArray()
	if not FileAccess.file_exists(path):
		return roots
	var data: Variant = JSON.parse_string(FileAccess.get_file_as_string(path))
	if not data is Dictionary:
		return roots
	for r in data.get(key, []):
		var s := normalize(str(r))
		if s.begins_with("/") and s.length() > 1 and not _has_bad_component(s):
			roots.append(s)
		else:
			push_warning("[pix-MCP] ignoring %s entry (must be absolute, no dot components): %s" % [key, str(r)])
	return roots


static func normalize(p: String) -> String:
	var s := p.strip_edges()
	while s.find("//") != -1:
		s = s.replace("//", "/")
	while s.length() > 1 and s.ends_with("/"):
		s = s.substr(0, s.length() - 1)
	return s


static func _has_control_chars(s: String) -> bool:
	for i in s.length():
		var c := s.unicode_at(i)
		if c < 32 or c == 127:
			return true
	return false


## True when any component is empty-dot, "..", or a dot-name (hidden). Checked on the RAW string, so
## "lnk/../x" can never be simplified into an allowed-looking path while the OS follows the link.
static func _has_bad_component(p: String) -> bool:
	for comp in p.split("/", false):
		if comp == "." or comp == ".." or comp.begins_with("."):
			return true
	return false


## Refuse if any existing component strictly below `root` is a symbolic link.
static func _has_symlink_below(root: String, p: String) -> bool:
	var rel := p.substr(root.length())
	var cur := root
	for comp in rel.split("/", false):
		var parent := cur
		cur = cur.path_join(comp)
		var d := DirAccess.open(parent)
		if d == null:
			return false   # parent does not exist yet: the rest will be created as real dirs/files
		# Link check FIRST (lstat semantics): a dangling link reports as non-existent but the OS would
		# still follow it on write (re-review 2026-11-06).
		if d.is_link(comp):
			return true
		if not (FileAccess.file_exists(cur) or DirAccess.dir_exists_absolute(cur)):
			return false
	return false


func is_path_allowed(p: String, for_write: bool) -> bool:
	if p.is_empty() or p.begins_with("~") or p.find("://") != -1 or p.find("\\") != -1:
		return false
	if not p.begins_with("/") or _has_control_chars(p) or _has_bad_component(p):
		return false
	var s := normalize(p)
	var roots: PackedStringArray = allowed_roots.duplicate()
	if not for_write:
		roots.append_array(read_roots)
	for root in roots:
		if s == root or s.begins_with(root + "/"):
			return not _has_symlink_below(root, s)
	return false


static func is_safe_name(v: String) -> bool:
	return not (v.find("/") != -1 or v.find("\\") != -1 or v == "." or v == ".." or _has_control_chars(v))


## Returns "" when OK, otherwise an error message naming the offending parameter.
func check_params(tool_name: String, params: Dictionary) -> String:
	var for_write: bool = not READ_TOOLS.has(tool_name)
	for key in PATH_KEYS:
		if params.has(key):
			var v := str(params[key])
			if v.is_empty():
				continue
			if not is_path_allowed(v, for_write):
				return "Path for '%s' is outside the allowed %s roots (%s). Configure %s/config.json." % [
					key, "write" if for_write else "read",
					", ".join(allowed_roots if for_write else allowed_roots + read_roots) if (allowed_roots.size() + read_roots.size()) > 0 else "none configured",
					config_dir]
	var name_keys: Array = NAME_KEYS.duplicate()
	name_keys.append_array(FILE_NAME_TOOLS.get(tool_name, []))
	for key in name_keys:
		if params.has(key) and not is_safe_name(str(params[key])):
			return "Parameter '%s' must be a plain name (no path separators or control characters)." % key
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
