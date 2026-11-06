## Build PixMcpBridge.pck from the reviewed sources (hardened fork).
## Usage (from the repo root):  godot --headless --script pack.gd
## Writes ONLY ./PixMcpBridge.pck. Install it yourself (Pixelorama > Preferences > Extensions) and
## record its SHA-256; nothing is copied into Pixelorama's data directory by this script.
## Shaders come from the official Pixelorama source (MIT): place them in pixelorama-source/addons/gdgifexporter/.
extends SceneTree

const PREFIX := "res://src/Extensions/PixMcpBridge/"
const PLUGIN_FILES := ["extension.json", "Main.tscn", "Main.gd", "command_handler.gd", "security.gd", "open_guard.gd", "guard_install.gd", "boot_guard.gd"]


func _init() -> void:
	var packer := PCKPacker.new()
	if packer.pck_start("PixMcpBridge.pck") != OK:
		push_error("cannot start PCK")
		quit(1)
		return
	for f in PLUGIN_FILES:
		var src: String = "pixelorama-plugin/" + str(f)
		if not FileAccess.file_exists(src):
			push_error("missing " + src)
			quit(1)
			return
		packer.add_file(PREFIX + f, src)
	# GIF exporter shaders / converter, resolved from the extension (same layout as upstream).
	for shader in ["lookup_similar.gdshader", "lookup_color.gdshader"]:
		var s: String = "pixelorama-source/addons/gdgifexporter/" + str(shader)
		if FileAccess.file_exists(s):
			packer.add_file("res://" + shader, s)
			packer.add_file("res://addons/gdgifexporter/" + shader, s)
		else:
			print("note: %s not found; GIF export may be unavailable" % s)
	if FileAccess.file_exists("pixelorama-plugin/converter.gd"):
		packer.add_file("res://addons/gdgifexporter/converter.gd", "pixelorama-plugin/converter.gd")
	if packer.flush(true) != OK:
		push_error("cannot flush PCK")
		quit(1)
		return
	print("Successfully packed PixMcpBridge.pck")
	quit(0)
