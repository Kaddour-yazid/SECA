const { app, BrowserWindow, dialog, shell } = require('electron');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const API_HOST = '127.0.0.1';
const API_PORT = 8000;
const API_READY_PATH = '/docs';

let mainWindow = null;
let backendProcess = null;
let backendStartedByApp = false;
let isQuitting = false;

function uniqueExistingPaths(paths) {
  return [...new Set(paths)].filter((candidate) => candidate && fs.existsSync(candidate));
}

function resolveFrontendEntry() {
  const appRoot = app.isPackaged ? app.getAppPath() : path.resolve(__dirname, '..');
  return path.join(appRoot, 'dist', 'index.html');
}

function resolveBackendDir() {
  const candidates = uniqueExistingPaths([
    path.resolve(__dirname, '..', 'backend'),
    path.join(process.resourcesPath, 'backend'),
    path.join(path.dirname(process.execPath), 'backend'),
  ]);

  return (
    candidates.find((candidate) => fs.existsSync(path.join(candidate, 'db', 'main.py'))) || null
  );
}

function resolvePythonCommand(backendDir) {
  const windowsVenv = path.join(backendDir, '.venv', 'Scripts', 'python.exe');
  const unixVenv = path.join(backendDir, '.venv', 'bin', 'python');

  if (fs.existsSync(windowsVenv)) {
    return { command: windowsVenv, prefixArgs: [] };
  }
  if (fs.existsSync(unixVenv)) {
    return { command: unixVenv, prefixArgs: [] };
  }
  if (process.platform === 'win32') {
    return { command: 'py', prefixArgs: ['-3.12'] };
  }
  return { command: 'python3', prefixArgs: [] };
}

function isBackendReachable() {
  return new Promise((resolve) => {
    const req = http.get(
      {
        host: API_HOST,
        port: API_PORT,
        path: API_READY_PATH,
        timeout: 2000,
      },
      (res) => {
        res.resume();
        resolve(res.statusCode && res.statusCode >= 200 && res.statusCode < 500);
      },
    );

    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitForBackend(timeoutMs = 30000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    // eslint-disable-next-line no-await-in-loop
    if (await isBackendReachable()) {
      return true;
    }
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, 750));
  }
  return false;
}

function startBackend() {
  const backendDir = resolveBackendDir();
  if (!backendDir) {
    throw new Error('Backend folder not found. Expected a valid SECA backend next to the desktop app.');
  }

  const dbDir = path.join(backendDir, 'db');
  const { command, prefixArgs } = resolvePythonCommand(backendDir);
  const args = [
    ...prefixArgs,
    '-m',
    'uvicorn',
    'main:app',
    '--host',
    API_HOST,
    '--port',
    String(API_PORT),
    '--app-dir',
    dbDir,
  ];

  backendProcess = spawn(command, args, {
    cwd: backendDir,
    env: {
      ...process.env,
      PYTHONUNBUFFERED: '1',
    },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  backendStartedByApp = true;

  backendProcess.stdout.on('data', (chunk) => {
    process.stdout.write(`[SECA backend] ${chunk}`);
  });

  backendProcess.stderr.on('data', (chunk) => {
    process.stderr.write(`[SECA backend] ${chunk}`);
  });

  backendProcess.on('exit', (code) => {
    backendProcess = null;
    if (!isQuitting && code !== 0 && mainWindow) {
      dialog.showErrorBox(
        'SECA Backend Stopped',
        `The backend process exited unexpectedly with code ${code}.`,
      );
    }
  });
}

function stopBackend() {
  if (!backendProcess || !backendStartedByApp) {
    return;
  }

  try {
    backendProcess.kill();
  } catch {
    // Ignore best-effort shutdown failures.
  } finally {
    backendProcess = null;
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1180,
    minHeight: 760,
    backgroundColor: '#0f172a',
    show: false,
    title: 'SECA',
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    void shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('ready-to-show', () => {
    mainWindow?.show();
  });
}

async function bootstrap() {
  createWindow();

  const frontendEntry = resolveFrontendEntry();
  if (!fs.existsSync(frontendEntry)) {
    throw new Error('Frontend build not found. Run "npm run build" before launching the desktop app.');
  }

  if (!(await isBackendReachable())) {
    startBackend();
  }

  const ready = await waitForBackend();
  if (!ready) {
    dialog.showErrorBox(
      'SECA Backend Unavailable',
      'The desktop app could not reach the backend on http://127.0.0.1:8000.\n\nCheck PostgreSQL and the backend configuration, then try again.',
    );
  }

  await mainWindow.loadFile(frontendEntry);
}

app.whenReady().then(async () => {
  try {
    await bootstrap();
  } catch (error) {
    dialog.showErrorBox(
      'SECA Desktop Startup Failed',
      error instanceof Error ? error.message : 'Unknown startup error.',
    );
    app.quit();
  }
});

app.on('before-quit', () => {
  isQuitting = true;
  stopBackend();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    void bootstrap();
  }
});
