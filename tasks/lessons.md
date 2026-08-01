# Lessons

- When streamlining, preserve explicitly valued interactive shell ergonomics like `Register-ArgumentCompleter` unless the user names them as removable.
- Treat PSReadLine configuration as core interactive shell behavior; do not remove it during repo slimming unless explicitly asked.
- Do not delete wrapper functions solely because a built-in exists; first compare semantics. `Update-Modules` adds discovery, reporting, prerelease support, throttling, and old-version cleanup.
- Keep user-valued on-demand utilities like `Get-StockPrice`; the cleanup target is startup network calls, not every function that can call an API.
- Video conversion helpers must not treat audio mapping as optional when their expected result includes audio; fail clearly and verify the produced media contains an audio stream.
- For broad MP4 compatibility, downmix nonstandard surround layouts such as `5.1(side)` to stereo AAC; avoid native AAC program-config-element layouts.
- Do not mutate a parameter inside a `process` block to calculate a per-item default; use a local variable so pipeline items cannot inherit a prior item's value.
