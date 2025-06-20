import * as vscode from 'vscode';
import axios from 'axios';

export function activate(context: vscode.ExtensionContext) {
  let disposable = vscode.commands.registerCommand('prism.scanCode', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showErrorMessage('No code file open!');
      return;
    }

    const code = editor.document.getText();

    const loading = vscode.window.setStatusBarMessage('🔍 Analyzing with PRism AI...');

    try {
      const res = await axios.post('http://127.0.0.1:8000/analyze', { code });
      const { vulnerability_score, suggestions } = res.data;

      vscode.window.showInformationMessage(`🔐 PRism Risk Score: ${vulnerability_score}%`);

      const panel = vscode.window.createWebviewPanel(
        'prismSuggestions',
        'PRism Suggestions',
        vscode.ViewColumn.Beside,
        {}
      );

      panel.webview.html = getWebviewContent(vulnerability_score, suggestions);
    } catch (error) {
      vscode.window.showErrorMessage('❌ Failed to connect to PRism backend');
    } finally {
      loading.dispose();
    }
  });

  context.subscriptions.push(disposable);
}

function getWebviewContent(score: number, suggestions: string[]): string {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>PRism Scan Results</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          margin: 0;
          padding: 0;
          background-color: #f4f4f9;
          color: #333;
        }
        header {
          background-color: #4CAF50;
          color: white;
          padding: 1rem;
          text-align: center;
        }
        .container {
          padding: 2rem;
        }
        .score {
          font-size: 1.5rem;
          font-weight: bold;
          color: #4CAF50;
          margin-bottom: 1rem;
        }
        .suggestions {
          margin-top: 1rem;
        }
        .suggestions h3 {
          color: #333;
        }
        .suggestions ul {
          list-style-type: none;
          padding: 0;
        }
        .suggestions li {
          background: #fff;
          margin: 0.5rem 0;
          padding: 0.75rem;
          border-radius: 5px;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
      </style>
    </head>
    <body>
      <header>
        <h1>🔍 PRism Scan Results</h1>
      </header>
      <div class="container">
        <div class="score">Vulnerability Score: ${score}%</div>
        <div class="suggestions">
          <h3>🛠️ Suggestions:</h3>
          <ul>
            ${suggestions.map(s => `<li>${s}</li>`).join('')}
          </ul>
        </div>
      </div>
    </body>
    </html>
  `;
}

export function deactivate() {}
