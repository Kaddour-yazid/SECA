const { app, BrowserWindow, dialog, shell } = require('electron');
const { randomUUID } = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const API_HOST = '127.0.0.1';
const API_PORT = 8000;
const API_READY_PATH = '/docs';
const DESKTOP_HEARTBEAT_DEFAULT_INTERVAL_MS = 15000;
const DESKTOP_HEARTBEAT_STOP_TIMEOUT_MS = 3000;

let mainWindow = null;
let backendProcess = null;
let backendStartedByApp = false;
let isQuitting = false;
let desktopHeartbeatTimer = null;
let desktopHeartbeatInFlight = false;
let desktopHeartbeatIntervalMs = DESKTOP_HEARTBEAT_DEFAULT_INTERVAL_MS;
let desktopSessionId = null;
let lastAuthToken = '';
let desktopDeviceIdentity = null;

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

function getDesktopDeviceIdentity() {
  if (desktopDeviceIdentity) {
    return desktopDeviceIdentity;
  }

  const userDataDir = app.getPath('userData');
  const identityPath = path.join(userDataDir, 'desktop-device.json');
  try {
    if (fs.existsSync(identityPath)) {
      const parsed = JSON.parse(fs.readFileSync(identityPath, 'utf8'));
      if (parsed && parsed.deviceId) {
        desktopDeviceIdentity = {
          deviceId: String(parsed.deviceId),
          hostname: os.hostname(),
        };
        return desktopDeviceIdentity;
      }
    }
  } catch {
    // Ignore and regenerate identity.
  }

  desktopDeviceIdentity = {
    deviceId: randomUUID(),
    hostname: os.hostname(),
  };

  try {
    fs.mkdirSync(userDataDir, { recursive: true });
    fs.writeFileSync(identityPath, JSON.stringify({ deviceId: desktopDeviceIdentity.deviceId }, null, 2), 'utf8');
  } catch {
    // Best-effort persistence only.
  }

  return desktopDeviceIdentity;
}

function requestJson({ method = 'GET', pathName, token, body, timeout = 5000 }) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = {
      Accept: 'application/json',
    };
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = http.request(
      {
        host: API_HOST,
        port: API_PORT,
        path: pathName,
        method,
        timeout,
        headers,
      },
      (res) => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          raw += chunk;
        });
        res.on('end', () => {
          const statusCode = res.statusCode || 500;
          let parsed = {};
          try {
            parsed = raw ? JSON.parse(raw) : {};
          } catch {
            parsed = raw ? { detail: raw } : {};
          }

          if (statusCode >= 200 && statusCode < 300) {
            resolve(parsed);
            return;
          }

          const detail =
            parsed && typeof parsed === 'object' && parsed.detail
              ? parsed.detail
              : `HTTP ${statusCode}`;
          reject(new Error(String(detail)));
        });
      },
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Request timeout'));
    });

    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

async function readRendererToken() {
  if (!mainWindow || mainWindow.isDestroyed()) {
    return '';
  }

  try {
    const token = await mainWindow.webContents.executeJavaScript(
      "(() => { try { return window.localStorage.getItem('token') || ''; } catch (error) { return ''; } })()",
      true,
    );
    return typeof token === 'string' ? token.trim() : '';
  } catch {
    return '';
  }
}

async function sendDesktopHeartbeat(token) {
  const device = getDesktopDeviceIdentity();
  const response = await requestJson({
    method: 'POST',
    pathName: '/desktop/session/heartbeat',
    token,
    body: {
      session_id: desktopSessionId,
      device_id: device.deviceId,
      hostname: device.hostname,
      app_version: app.getVersion(),
      platform: process.platform,
    },
  });

  const session = response && response.session ? response.session : null;
  if (session && session.session_id) {
    desktopSessionId = session.session_id;
  }
  if (response && Number.isFinite(response.heartbeat_interval_seconds)) {
    desktopHeartbeatIntervalMs = Math.max(5000, Number(response.heartbeat_interval_seconds) * 1000);
  }
}

async function stopDesktopSession(reason = 'app-exit', tokenOverride = '') {
  const token = tokenOverride || lastAuthToken;
  if (!token || !desktopSessionId) {
    desktopSessionId = null;
    return;
  }

  const device = getDesktopDeviceIdentity();
  try {
    await requestJson({
      method: 'POST',
      pathName: '/desktop/session/stop',
      token,
      body: {
        session_id: desktopSessionId,
        device_id: device.deviceId,
        reason,
      },
      timeout: DESKTOP_HEARTBEAT_STOP_TIMEOUT_MS,
    });
  } catch {
    // Best-effort stop; backend timeout fallback still handles crashes.
  } finally {
    desktopSessionId = null;
  }
}

async function runDesktopHeartbeatTick() {
  if (desktopHeartbeatInFlight) {
    return;
  }

  desktopHeartbeatInFlight = true;
  try {
    const token = await readRendererToken();
    if (!token) {
      if (lastAuthToken && desktopSessionId) {
        await stopDesktopSession('token-cleared', lastAuthToken);
      }
      lastAuthToken = '';
      return;
    }

    if (lastAuthToken && token !== lastAuthToken && desktopSessionId) {
      await stopDesktopSession('token-rotated', lastAuthToken);
    }

    lastAuthToken = token;
    await sendDesktopHeartbeat(token);
  } catch (error) {
    process.stderr.write(`[SECA desktop] Heartbeat error: ${error instanceof Error ? error.message : String(error)}\n`);
  } finally {
    desktopHeartbeatInFlight = false;
  }
}

function scheduleDesktopHeartbeat() {
  if (desktopHeartbeatTimer) {
    clearTimeout(desktopHeartbeatTimer);
  }
  desktopHeartbeatTimer = setTimeout(async () => {
    await runDesktopHeartbeatTick();
    scheduleDesktopHeartbeat();
  }, desktopHeartbeatIntervalMs);
}

function startDesktopHeartbeatLoop() {
  if (desktopHeartbeatTimer) {
    clearTimeout(desktopHeartbeatTimer);
  }
  void runDesktopHeartbeatTick();
  scheduleDesktopHeartbeat();
}

function stopDesktopHeartbeatLoop() {
  if (desktopHeartbeatTimer) {
    clearTimeout(desktopHeartbeatTimer);
    desktopHeartbeatTimer = null;
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
  startDesktopHeartbeatLoop();
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
  stopDesktopHeartbeatLoop();
  void stopDesktopSession('app-exit');
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
