# Entries🚪

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-brightgreen.svg"></a>
  <img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat">
  <a href="https://github.com/kawakatz/Entries/releases/latest"><img src="https://img.shields.io/github/v/release/kawakatz/Entries?display_name=tag"></a>
  <a href="https://github.com/kawakatz/Entries/actions/workflows/build.yml"><img src="https://github.com/kawakatz/Entries/actions/workflows/build.yml/badge.svg"></a>
  <a href="https://x.com/kawakatz"><img src="https://img.shields.io/twitter/follow/kawakatz"></a>
</p>

A Windows attack-surface entry point enumerator for security research agents.<br>
It was designed for agents and implemented by agents.

## Usage

Run as Administrator for the most complete results.

```text
Entries.exe --path <regex> [--type <types>] [--json] [--verbose]
```

`--type` accepts a comma-separated list; omitting it enables all types:

```text
tcp udp pipe shm alpc rpc http svc mail com drv task wmi shell assoc devif
browser fw appx etw win filter crypto persist kobj
```

```bat
Entries.exe --path ".*" --type pipe --json
```

`--json` writes `type`, `name`, `details`, `pid`, `privilege`, and `path` to
stdout; diagnostics go to stderr. Exit status `0` means complete, `2` means a
valid partial result, and `1` means failure.
