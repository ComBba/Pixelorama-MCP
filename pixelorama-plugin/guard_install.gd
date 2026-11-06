## Hardened fork — installs open_guard.gd on the OpenSave autoload by swapping its script and copying
## every member value (OpenSave 1.2.4 keeps plain state: backup path, autosave timer, importer maps).
## Used by boot_guard.gd (mode "boot", before the main scene opens command-line files) and by the
## bridge extension (mode "runtime", fallback). Returns the guard mode now active, or "off".
extends RefCounted

const OPEN_SAVE_SCRIPT := "res://src/Autoload/OpenSave.gd"
const META := &"pix_mcp_open_guard"


static func install(tree: SceneTree, mode: String, guard: Script) -> String:
	var open_save := tree.root.get_node_or_null("OpenSave")
	if open_save == null:
		push_error("[pix-MCP guard] OpenSave autoload not found; open guard NOT installed")
		return "off"
	var current: Script = open_save.get_script()
	if current != null and current.get_script_constant_map().has("PIX_MCP_OPEN_GUARD"):
		return str(open_save.get_meta(META, mode))
	if current == null or current.resource_path != OPEN_SAVE_SCRIPT:
		push_error("[pix-MCP guard] OpenSave has an unexpected script (%s); open guard NOT installed" % [
			current.resource_path if current else "none"])
		return "off"
	if guard == null:
		push_error("[pix-MCP guard] open_guard.gd failed to load; open guard NOT installed")
		return "off"
	var saved := {}
	for prop in open_save.get_property_list():
		if prop["usage"] & PROPERTY_USAGE_SCRIPT_VARIABLE:
			saved[prop["name"]] = open_save.get(prop["name"])
	open_save.set_script(guard)
	for key in saved:
		open_save.set(key, saved[key])
	open_save.set_meta(META, mode)
	print("[pix-MCP guard] open guard installed (%s): .pxo pre-scan; .tres/.pck/.zip refused; .ora/.kra/.json scanned" % mode)
	return mode

