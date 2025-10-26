const vscode = require('vscode');
const fs = require('fs');
const path = require('path');

async function activate(context) {
  const disposable = vscode.commands.registerCommand(
    'luraph-reverse-mapping.lookupOriginal',
    async () => {
      if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
        vscode.window.showErrorMessage('Open the deobfuscation workspace before running this command.');
        return;
      }

      const selected = vscode.window.activeTextEditor
        ? vscode.window.activeTextEditor.document.getText(vscode.window.activeTextEditor.selection).trim()
        : '';

      const identifier = await vscode.window.showInputBox({
        prompt: 'Enter the deobfuscated identifier to trace back to the original name',
        value: selected,
        validateInput: (value) => (!value ? 'Identifier cannot be empty' : undefined),
      });

      if (!identifier) {
        return;
      }

      const mappingContext = await loadMappingContext();
      if (!mappingContext) {
        return;
      }

      const { reverseMap, lockPath, mappingPath } = mappingContext;
      const originals = reverseMap.get(identifier);

      if (!originals || originals.length === 0) {
        vscode.window.showInformationMessage(
          `No original identifier was found for "${identifier}" in ${path.relative(vscode.workspace.workspaceFolders[0].uri.fsPath, mappingPath)}.`
        );
        return;
      }

      let chosen = originals[0];
      if (originals.length > 1) {
        const picked = await vscode.window.showQuickPick(originals, {
          placeHolder: 'Multiple obfuscated identifiers map to this name – choose one to navigate to',
        });
        if (!picked) {
          return;
        }
        chosen = picked;
      }

      const location = await findFirstMatch(chosen);
      if (!location) {
        vscode.window.showWarningMessage(
          `Found "${chosen}" in mapping (${path.relative(vscode.workspace.workspaceFolders[0].uri.fsPath, lockPath)}), but it was not located in the workspace.`
        );
        return;
      }

      const document = await vscode.workspace.openTextDocument(location.uri);
      const editor = await vscode.window.showTextDocument(document);
      const targetRange = ensureRange(location.range);
      if (targetRange) {
        editor.selection = new vscode.Selection(targetRange.start, targetRange.end);
        editor.revealRange(targetRange, vscode.TextEditorRevealType.InCenter);
      }
    }
  );

  context.subscriptions.push(disposable);
}

function ensureRange(rangeCandidate) {
  if (!rangeCandidate) {
    return null;
  }
  if (rangeCandidate instanceof vscode.Range) {
    return rangeCandidate;
  }
  if (Array.isArray(rangeCandidate)) {
    return ensureRange(rangeCandidate[0]);
  }
  if (typeof rangeCandidate.start === 'object' && typeof rangeCandidate.end === 'object') {
    const start = new vscode.Position(rangeCandidate.start.line, rangeCandidate.start.character);
    const end = new vscode.Position(rangeCandidate.end.line, rangeCandidate.end.character);
    return new vscode.Range(start, end);
  }
  return null;
}

async function loadMappingContext() {
  try {
    const lockUri = await findFirstFile('**/mapping.lock');
    let mappingUri = null;
    let lockPath = null;

    if (lockUri) {
      lockPath = lockUri.fsPath;
      const lockData = JSON.parse(await fs.promises.readFile(lockUri.fsPath, 'utf8'));
      const candidate = typeof lockData.mapping_path === 'string' ? lockData.mapping_path.trim() : '';
      if (candidate) {
        const resolved = path.resolve(path.dirname(lockUri.fsPath), candidate);
        if (await fileExists(resolved)) {
          mappingUri = vscode.Uri.file(resolved);
        }
      }
      if (!mappingUri) {
        const fallback = path.join(path.dirname(lockUri.fsPath), 'mapping.json');
        if (await fileExists(fallback)) {
          mappingUri = vscode.Uri.file(fallback);
        }
      }
    }

    if (!mappingUri) {
      const mappingOnlyUri = await findFirstFile('**/mapping.json');
      if (!mappingOnlyUri) {
        vscode.window.showErrorMessage('Unable to locate mapping.lock or mapping.json in the workspace.');
        return null;
      }
      mappingUri = mappingOnlyUri;
      lockPath = mappingOnlyUri.fsPath;
    }

    const renameMap = await readRenameMap(mappingUri.fsPath);
    const reverseMap = new Map();
    for (const [original, renamed] of renameMap.entries()) {
      const bucket = reverseMap.get(renamed) || [];
      bucket.push(original);
      reverseMap.set(renamed, bucket);
    }

    return {
      reverseMap,
      lockPath: lockPath ? lockPath : mappingUri.fsPath,
      mappingPath: mappingUri.fsPath,
    };
  } catch (error) {
    vscode.window.showErrorMessage(`Failed to read mapping metadata: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

async function findFirstMatch(identifier) {
  return new Promise((resolve) => {
    const tokenSource = new vscode.CancellationTokenSource();
    let resolved = false;

    vscode.workspace
      .findTextInFiles({ pattern: identifier }, {}, (result) => {
        if (resolved || !result || !result.ranges || result.ranges.length === 0) {
          return;
        }
        const range = Array.isArray(result.ranges) ? result.ranges[0] : result.ranges;
        resolved = true;
        resolve({ uri: result.uri, range });
        tokenSource.cancel();
      }, tokenSource.token)
      .then(
        () => {
          if (!resolved) {
            resolved = true;
            resolve(null);
          }
        },
        () => {
          if (!resolved) {
            resolved = true;
            resolve(null);
          }
        }
      );
  });
}

async function findFirstFile(globPattern) {
  const uris = await vscode.workspace.findFiles(globPattern, '**/node_modules/**', 1);
  return uris && uris.length > 0 ? uris[0] : null;
}

async function readRenameMap(filePath) {
  const content = await fs.promises.readFile(filePath, 'utf8');
  const data = JSON.parse(content);
  const map = new Map();

  const addEntry = (source, target) => {
    if (typeof source !== 'string' || typeof target !== 'string') {
      return;
    }
    const trimmedSource = source.trim();
    const trimmedTarget = target.trim();
    if (!trimmedSource || !trimmedTarget) {
      return;
    }
    map.set(trimmedSource, trimmedTarget);
  };

  if (Array.isArray(data)) {
    for (const entry of data) {
      if (entry && typeof entry === 'object') {
        addEntry(entry.name || entry.source || entry.identifier, entry.recommended_name || entry.target || entry.rename);
      }
    }
  } else if (data && typeof data === 'object') {
    const values = Object.values(data);
    const simple = values.every((value) => typeof value === 'string');
    if (simple) {
      for (const [key, value] of Object.entries(data)) {
        addEntry(key, value);
      }
    } else {
      for (const key of ['renames', 'mapping', 'items', 'rows']) {
        const entries = data[key];
        if (Array.isArray(entries)) {
          for (const entry of entries) {
            if (entry && typeof entry === 'object') {
              addEntry(entry.name || entry.source || entry.identifier, entry.recommended_name || entry.target || entry.rename);
            }
          }
        } else if (entries && typeof entries === 'object') {
          for (const [name, target] of Object.entries(entries)) {
            addEntry(name, target);
          }
        }
      }
    }
  }

  if (map.size === 0) {
    throw new Error(`No rename entries were found in ${filePath}`);
  }

  return map;
}

async function fileExists(candidatePath) {
  try {
    await fs.promises.access(candidatePath, fs.constants.F_OK);
    return true;
  } catch (error) {
    return false;
  }
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
