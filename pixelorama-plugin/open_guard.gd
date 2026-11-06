## Hardened fork — guard for files a PERSON opens in Pixelorama: Finder / `open -a` / double-click /
## Dock drop (on macOS each of these starts a NEW Pixelorama process with the file on the command
## line, opened from Main._ready), File > Open, recent projects, drag & drop onto the window and
## session-backup restore. Every one of those entry points calls OpenSave.handle_loading_file() or
## OpenSave.open_pxo_file() on the OpenSave autoload, so guard_install.gd swaps that autoload's script
## for this subclass (state copied) and the same pre-scan the MCP `open_project` tool uses runs before
## Pixelorama's own loader. Installed at boot by boot_guard.gd (an autoload registered in
## user://override.cfg) and, as a fallback, by the bridge extension's node. See HARDENING.md.
extends "res://src/Autoload/OpenSave.gd"

const PIX_MCP_OPEN_GUARD := true
const _Security := preload("security.gd")
const GUARD_TAG := "[pix-MCP guard] "


func handle_loading_file(file: String, force_import_dialog_on_images := false) -> void:
	var p := file.replace("\\", "/")
	# .pxo is checked in open_pxo_file(), which backups and the MCP bridge also call directly.
	if p.get_extension().to_lower() != "pxo":
		var why := _Security.check_open_file(p)
		if not why.is_empty():
			_refuse(p, why)
			return
	super(file, force_import_dialog_on_images)


func open_pxo_file(path: String, is_backup := false, replace_empty := true) -> void:
	var why := _Security.check_pxo(path)
	if not why.is_empty():
		_refuse(path, why)
		return
	super(path, is_backup, replace_empty)


func _refuse(path: String, why: String) -> void:
	push_warning(GUARD_TAG + "refused %s: %s" % [path, why])
	print(GUARD_TAG + "refused %s: %s" % [path, why])
	# At boot the dialog nodes may not exist yet; show the popup once the main scene is up.
	_popup.call_deferred(
		"Blocked by the pix-MCP open guard:\n%s\n\nFile: %s" % [why, path.uri_decode().get_file()]
	)


func _popup(text: String) -> void:
	if is_instance_valid(Global.control):
		Global.popup_error(text)
