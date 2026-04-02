# SECA Frontend Workspace

This folder contains the React + TypeScript frontend for SECA.

For full project documentation, setup instructions, and backend details, see the repository root README:

- `../README.md`
- PostgreSQL backend setup for this clone: `backend/README_POSTGRES.md`

## Local Commands

```powershell
npm install
npm run dev
npm run build
npm run desktop:start
```

Optional frontend API override (`project_postgres/.env`):

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

Backend (PostgreSQL) quick start:

```powershell
cd backend
.\run_backend.bat
```

Default dev URL:

- `http://127.0.0.1:5173`

## Desktop App

This project can also run as a Windows desktop app with Electron while keeping the existing PostgreSQL backend configuration.

Desktop launch:

```powershell
npm run desktop:start
```

Portable Windows build:

```powershell
npm run desktop:pack
```

Notes:

- The desktop app starts the backend on `127.0.0.1:8000` if it is not already running.
- It reuses the backend folder and `.env` configuration shipped with the build.
- Your PostgreSQL configuration remains unchanged.

Desktop remote-backend mode for a second machine:

- Copy `desktop-config.example.json` to `desktop-config.json`
- Set:

```json
{
  "apiBaseUrl": "http://HOST_MACHINE_IP:8000"
}
```

- Place `desktop-config.json` next to the desktop app or inside `project_postgres/`
- In this mode the desktop client will:
  - connect to the remote backend instead of `127.0.0.1`
  - keep the desktop heartbeat running automatically after app launch/login
  - avoid starting a local backend on the client machine
