## Hardened fork — boot-time installer for the open guard. Registered as an autoload in
## user://override.cfg (Pixelorama's project_settings_override), copied with open_guard.gd,
## guard_install.gd and security.gd into user://pix_mcp_guard/. Autoloads enter the tree before the
## main scene, so the guard is active before Main._ready() opens files from the command line
## (Finder / `open -a` / double-click start a new process with the file as an argument on macOS).
extends Node


func _enter_tree() -> void:
	preload("guard_install.gd").install(get_tree(), "boot", preload("open_guard.gd"))
