const { app, BrowserWindow, dialog, shell } = require('electron');
const { randomUUID } = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

function uniqueExistingPaths(paths) {
  return [...new Set(paths)].filter((candidate) => candidate && fs.existsSync(candidate));
}

function loadDesktopConfig() {
  const candidates = uniqueExistingPaths([
    path.resolve(__dirname, '..', 'desktop-config.json'),
    path.join(process.cwd(), 'desktop-config.json'),
    path.join(path.dirname(process.execPath), 'desktop-config.json'),
    path.join(process.resourcesPath, 'desktop-config.json'),
  ]);

  for (const configPath of candidates) {
    try {
      const parsed = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      if (parsed && typeof parsed === 'object') {
        return parsed;
      }
    } catch {
      // Ignore malformed config files and continue to fallback env/defaults.
    }
  }

  return {};
}

const desktopConfig = loadDesktopConfig();
const rawApiBase =
  (process.env.SECA_DESKTOP_API_BASE_URL || desktopConfig.apiBaseUrl || 'http://127.0.0.1:8000').trim();
const normalizedApiBase = rawApiBase.replace(/\/+$/, '');
const apiUrl = new URL(normalizedApiBase);
const API_BASE_URL = normalizedApiBase;
const API_HOST = apiUrl.hostname || '127.0.0.1';
const API_PORT = Number(apiUrl.port || (apiUrl.protocol === 'https:' ? 443 : 80));
const API_PROTOCOL = apiUrl.protocol || 'http:';
const API_READY_PATH = '/docs';
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);
const API_IS_LOCAL = LOOPBACK_HOSTS.has(API_HOST);
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
let assignedProxyConfig = null;

function getManagedProxyStatePath() {
  return path.join(app.getPath('userData'), 'managed-proxy-state.json');
}

function readManagedProxyState() {
  try {
    const statePath = getManagedProxyStatePath();
    if (!fs.existsSync(statePath)) {
      return null;
    }
    return JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch {
    return null;
  }
}

function writeManagedProxyState(data) {
  try {
    const statePath = getManagedProxyStatePath();
    fs.mkdirSync(path.dirname(statePath), { recursive: true });
    fs.writeFileSync(statePath, JSON.stringify(data, null, 2), 'utf8');
  } catch {
    // Best-effort persistence only.
  }
}

function clearManagedProxyState() {
  try {
    const statePath = getManagedProxyStatePath();
    if (fs.existsSync(statePath)) {
      fs.unlinkSync(statePath);
    }
  } catch {
    // Ignore cleanup failures.
  }
}

function parseProxyTarget(rawValue) {
  const raw = String(rawValue || '').trim();
  if (!raw) {
    return { host: null, port: null, raw };
  }

  let candidate = raw;
  if (raw.includes('=')) {
    const segments = raw.split(';').map((segment) => segment.trim()).filter(Boolean);
    const preferred =
      segments.find((segment) => segment.toLowerCase().startsWith('https=')) ||
      segments.find((segment) => segment.toLowerCase().startsWith('http=')) ||
      segments[0];
    candidate = preferred.includes('=') ? preferred.split('=').slice(1).join('=').trim() : preferred;
  }

  candidate = candidate.replace(/^https?:\/\//i, '').trim();
  const hostPortMatch = candidate.match(/^([^:;]+)(?::(\d+))?/);
  if (!hostPortMatch) {
    return { host: null, port: null, raw };
  }

  const host = (hostPortMatch[1] || '').trim() || null;
  const parsedPort = hostPortMatch[2] ? Number(hostPortMatch[2]) : null;
  return {
    host,
    port: Number.isFinite(parsedPort) ? parsedPort : null,
    raw,
  };
}

function getWindowsProxyState() {
  if (process.platform !== 'win32') {
    return {
      supported: false,
      enabled: false,
      host: null,
      port: null,
      raw: null,
      status: 'unsupported',
    };
  }

  const script = [
    '$key = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"',
    '$item = Get-ItemProperty -Path $key',
    '$result = @{',
    '  ProxyEnable = [bool]($item.ProxyEnable)',
    '  ProxyServer = [string]($item.ProxyServer)',
    '}',
    '$result | ConvertTo-Json -Compress',
  ].join('; ');

  try {
    const powershell = process.env.ComSpec && process.platform === 'win32' ? 'powershell.exe' : 'powershell';
    const probe = spawnSync(powershell, ['-NoProfile', '-Command', script], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 4000,
    });

    if (probe.status !== 0) {
      return {
        supported: true,
        enabled: false,
        host: null,
        port: null,
        raw: null,
        status: 'error',
      };
    }

    const parsed = JSON.parse((probe.stdout || '').trim() || '{}');
    const enabled = Boolean(parsed.ProxyEnable);
    const target = parseProxyTarget(parsed.ProxyServer);
    return {
      supported: true,
      enabled: enabled && Boolean(target.host),
      host: enabled ? target.host : null,
      port: enabled ? target.port : null,
      raw: target.raw || null,
      status: enabled && target.host ? 'enabled' : 'disabled',
    };
  } catch {
    return {
      supported: true,
      enabled: false,
      host: null,
      port: null,
      raw: null,
      status: 'error',
    };
  }
}

function setWindowsProxyState(state) {
  if (process.platform !== 'win32') {
    return false;
  }

  const enabled = Boolean(state && state.enabled);
  const rawProxyServer = enabled
    ? String(state.raw || `${state.host || ''}${state.port ? `:${state.port}` : ''}`).trim()
    : String((state && state.raw) || '').trim();
  const escapedProxyServer = rawProxyServer.replace(/'/g, "''");
  const script = [
    '$key = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"',
    `$proxyEnable = ${enabled ? 1 : 0}`,
    `$proxyServer = '${escapedProxyServer}'`,
    'Set-ItemProperty -Path $key -Name ProxyEnable -Value $proxyEnable',
    'Set-ItemProperty -Path $key -Name ProxyServer -Value $proxyServer',
  ].join('; ');

  try {
    const powershell = process.env.ComSpec && process.platform === 'win32' ? 'powershell.exe' : 'powershell';
    const probe = spawnSync(powershell, ['-NoProfile', '-Command', script], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 5000,
    });
    return probe.status === 0;
  } catch {
    return false;
  }
}

function restoreManagedProxyIfNeeded() {
  const stored = readManagedProxyState();
  if (!stored || !stored.original) {
    return false;
  }

  const restored = setWindowsProxyState(stored.original);
  if (restored) {
    clearManagedProxyState();
  }
  return restored;
}

function ensureAdminProxyApplied(assignment) {
  if (!assignment || !assignment.enabled || !assignment.proxy_host || !assignment.proxy_port) {
    restoreManagedProxyIfNeeded();
    return false;
  }

  const stored = readManagedProxyState();
  if (!stored || !stored.original) {
    const current = getWindowsProxyState();
    writeManagedProxyState({
      original: {
        enabled: Boolean(current.enabled),
        host: current.host || null,
        port: current.port || null,
        raw: current.raw || '',
      },
    });
  }

  return setWindowsProxyState({
    enabled: true,
    host: assignment.proxy_host,
    port: assignment.proxy_port,
    raw: `${assignment.proxy_host}:${assignment.proxy_port}`,
  });
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
    const client = API_PROTOCOL === 'https:' ? https : http;
    const req = client.get(
      {
        protocol: API_PROTOCOL,
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

function getLocalIPv4Addresses() {
  const networkMap = os.networkInterfaces();
  const addresses = [];
  for (const entries of Object.values(networkMap)) {
    for (const entry of entries || []) {
      if (!entry || entry.internal || entry.family !== 'IPv4') {
        continue;
      }
      addresses.push(entry.address);
    }
  }
  return [...new Set(addresses)];
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
    const targetUrl = new URL(pathName, `${API_BASE_URL}/`);
    const client = targetUrl.protocol === 'https:' ? https : http;
    const req = client.request(
      {
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname,
        port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
        path: `${targetUrl.pathname}${targetUrl.search}`,
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
  const proxyState = getWindowsProxyState();
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
      local_ips: getLocalIPv4Addresses(),
      proxy_host: proxyState.enabled ? proxyState.host : null,
      proxy_port: proxyState.enabled ? proxyState.port : null,
    },
  });

  const session = response && response.session ? response.session : null;
  if (session && session.session_id) {
    desktopSessionId = session.session_id;
  }
  if (response && response.proxy_assignment) {
    assignedProxyConfig = response.proxy_assignment;
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
      restoreManagedProxyIfNeeded();
      assignedProxyConfig = null;
      lastAuthToken = '';
      return;
    }

    if (lastAuthToken && token !== lastAuthToken && desktopSessionId) {
      await stopDesktopSession('token-rotated', lastAuthToken);
    }

    lastAuthToken = token;
    let currentUser = null;
    try {
      currentUser = await requestJson({
        method: 'GET',
        pathName: '/me',
        token,
      });
    } catch {
      currentUser = null;
    }

    if (currentUser && currentUser.is_admin) {
      try {
        const config = await requestJson({
          method: 'GET',
          pathName: '/desktop/session/config',
          token,
        });
        assignedProxyConfig = config && config.proxy_assignment ? config.proxy_assignment : null;
        if (config && Number.isFinite(config.heartbeat_interval_seconds)) {
          desktopHeartbeatIntervalMs = Math.max(5000, Number(config.heartbeat_interval_seconds) * 1000);
        }
        ensureAdminProxyApplied(assignedProxyConfig);
      } catch {
        assignedProxyConfig = null;
      }
    } else {
      assignedProxyConfig = null;
      restoreManagedProxyIfNeeded();
    }

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

  if (!API_IS_LOCAL) {
    mainWindow.webContents.session.webRequest.onBeforeRequest(
      {
        urls: [
          'http://127.0.0.1:8000/*',
          'http://localhost:8000/*',
        ],
      },
      (details, callback) => {
        try {
          const requested = new URL(details.url);
          const redirected = new URL(`${requested.pathname}${requested.search}`, `${API_BASE_URL}/`);
          callback({ redirectURL: redirected.toString() });
        } catch {
          callback({});
        }
      },
    );
  }

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

  if (API_IS_LOCAL && !(await isBackendReachable())) {
    startBackend();
  }

  const ready = await waitForBackend();
  if (!ready) {
    dialog.showErrorBox(
      'SECA Backend Unavailable',
      `The desktop app could not reach the backend on ${API_BASE_URL}.\n\nCheck PostgreSQL, backend access, and desktop API configuration, then try again.`,
    );
  }

  await mainWindow.loadFile(frontendEntry);
  startDesktopHeartbeatLoop();
}

app.whenReady().then(async () => {
  try {
    restoreManagedProxyIfNeeded();
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
  restoreManagedProxyIfNeeded();
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
