# Bulwark for VS Code

Runs the `bulwark` CLI on your workspace and shows findings as diagnostics (squiggles and the Problems panel).

1. Install the CLI (`scripts/install.sh`) and make sure `bulwark` is on your PATH.
2. Run **Bulwark: Scan workspace** from the command palette.
3. Optional: set `bulwark.scanOnSave`.

Package with `npx @vscode/vsce package`. This extension only reads SARIF from the CLI; no code leaves your machine.
