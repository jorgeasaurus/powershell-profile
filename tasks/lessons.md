# Lessons

- When streamlining, preserve explicitly valued interactive shell ergonomics like `Register-ArgumentCompleter` unless the user names them as removable.
- Treat PSReadLine configuration as core interactive shell behavior; do not remove it during repo slimming unless explicitly asked.
- Do not delete wrapper functions solely because a built-in exists; first compare semantics. `Update-Modules` adds discovery, reporting, prerelease support, throttling, and old-version cleanup.
- Keep user-valued on-demand utilities like `Get-StockPrice`; the cleanup target is startup network calls, not every function that can call an API.
