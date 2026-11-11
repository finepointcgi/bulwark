// Runs `bulwark scan --format sarif` and publishes the results as VS Code diagnostics.
// No dependencies: only the vscode API and Node's child_process.
const vscode = require("vscode");
const cp = require("child_process");
const path = require("path");

const LEVELS = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  note: vscode.DiagnosticSeverity.Information,
  none: vscode.DiagnosticSeverity.Hint,
};

/** Converts a SARIF log into a Map(uri string -> Diagnostic[]). Exported for tests. */
function toDiagnostics(sarif, root) {
  const byFile = new Map();
  for (const run of sarif.runs || []) {
    for (const result of run.results || []) {
      const physical = result.locations?.[0]?.physicalLocation;
      const uri = physical?.artifactLocation?.uri;
      if (!uri) continue;
      const region = physical.region || {};
      const line = Math.max(0, (region.startLine || 1) - 1);
      const endLine = Math.max(line, (region.endLine || region.startLine || 1) - 1);
      const range = new vscode.Range(line, 0, endLine, Number.MAX_SAFE_INTEGER);
      const diagnostic = new vscode.Diagnostic(range, result.message?.text || result.ruleId, LEVELS[result.level] ?? LEVELS.warning);
      diagnostic.source = "bulwark";
      diagnostic.code = result.ruleId;
      const file = vscode.Uri.file(path.resolve(root, decodeURIComponent(uri))).toString();
      if (!byFile.has(file)) byFile.set(file, []);
      byFile.get(file).push(diagnostic);
    }
  }
  return byFile;
}

function activate(context) {
  const collection = vscode.languages.createDiagnosticCollection("bulwark");
  const output = vscode.window.createOutputChannel("Bulwark");
  let running = false;

  async function scan() {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder || running) return;
    running = true;
    const config = vscode.workspace.getConfiguration("bulwark");
    const args = ["scan", folder.uri.fsPath, "--format", "sarif", "--fail-on", "none", ...config.get("extraArguments", [])];
    await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: "Bulwark scanning…" }, () =>
      new Promise((resolve) => {
        cp.execFile(config.get("executable", "bulwark"), args, { maxBuffer: 256 * 1024 * 1024 }, (error, stdout, stderr) => {
          if (stderr) output.appendLine(stderr);
          try {
            const sarif = JSON.parse(stdout);
            collection.clear();
            for (const [uri, diagnostics] of toDiagnostics(sarif, folder.uri.fsPath)) {
              collection.set(vscode.Uri.parse(uri), diagnostics);
            }
          } catch (e) {
            vscode.window.showErrorMessage(`Bulwark: could not read scan results (${error?.message || e.message}). See the Bulwark output channel.`);
          }
          resolve();
        });
      }));
    running = false;
  }

  context.subscriptions.push(
    collection, output,
    vscode.commands.registerCommand("bulwark.scan", scan),
    vscode.workspace.onDidSaveTextDocument(() => { if (vscode.workspace.getConfiguration("bulwark").get("scanOnSave")) scan(); }),
  );
}

function deactivate() {}

module.exports = { activate, deactivate, toDiagnostics };
