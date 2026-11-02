# Bergsson Mod Scanner

A Windows tool that audits Minecraft mod jars for **cheats, malware and obfuscation** - including cheat code
hidden inside otherwise legitimate mods - and verifies every file against **Modrinth**.

## What it checks

- **Behavior, not names.** Reads which game internals each class actually calls (Fabric intermediary,
  Mojang and MCP names) and flags autoclickers, timed attacks (KillAura/TriggerBot), forged movement
  packets, knockback cancelling, hidden hotkeys, self-deletion and mod-list tampering - even in
  obfuscated or innocently named classes.
- **Diff against the official file.** A jar that claims to be a Modrinth mod but isn't one of its files is
  compared entry-by-entry with the official download of that exact version; injected or modified classes
  are named.
- **Injected-code outliers.** Classes compiled for a different Java version than their package, or with a
  later timestamp than the rest of the jar; class files or jars disguised as resources.
- **Malware.** Discord/Telegram exfiltration, token, browser and wallet theft, encrypted payloads loaded
  with `defineClass`, Java agents, multi-loader droppers.
- **Obfuscation.** IlIl / unicode / keyword class names, string encryption, zip tricks, obfuscator watermarks.
- **Known clients and modules** by name (Wurst, Meteor, LiquidBounce, KillAura, Scaffold, X-Ray, ...).
- **Nested jars** (Fabric jar-in-jar, Forge jarjar) are opened recursively.
- **Live game detection.** Finds the running instance's real mods folder by reading the `javaw` process's
  command line and working directory.

Tested against 41 popular Modrinth mods: 40 come out clean (Tweakeroo is flagged on purpose - it sends its
own movement packets and has scaffold-style placement).

## Build

Requires Windows 10/11 and Visual Studio (or Build Tools) with the C++ workload.

```bat
build.bat
```

This produces `BergssonModScanner.exe`. Dear ImGui v1.91.8 is included in `third_party/imgui`.

## Usage

- Run `BergssonModScanner.exe` to open the app. Start Minecraft and click **Detect game**, choose a folder,
  or drop a mods folder / `.jar` files onto the window. Shortcuts: `F5` scan, `Ctrl+O` open folder,
  `Ctrl+E` export report, arrow keys to move through results.
- Command line: `BergssonModScanner.exe [paths...] [--detect] [--offline] [--verbose] [--sigs file]`.
  Set `CF_API_KEY` to also check CurseForge.
- Extra signatures can be added in `bergsson_sigs.txt` next to the exe:
  `weight|kind|pattern|label` (kind = `cheat`, `malware`, `suspicious` or `obf`; prefix the pattern with `=`
  for word-boundary matching).

**Quarantine** moves a jar to `%LOCALAPPDATA%\Bergsson\Quarantine` and renames it so no launcher loads it.
Nothing is ever deleted.

## Project layout

| File | Contents |
|---|---|
| `scanner_core.h` | Scanning engine: zip/inflate, class parsing, signatures, behavior rules, Modrinth/CurseForge lookups, game detection, CLI |
| `bergsson.cpp` | Dear ImGui + DirectX 11 interface and entry point |
| `build.bat` | MSVC build script |

## Limitations

Results are heuristic - review flagged files before acting on them. Code compiled into native libraries
can't be analyzed, and a cheat that is both unlisted on Modrinth and free of recognizable behavior can
still slip through.
