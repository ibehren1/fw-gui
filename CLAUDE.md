# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FW-GUI is a Flask web application for visually creating and managing VyOS firewall configurations. Users create firewall chains, filters, groups, interfaces, and flowtables through web forms, then push generated VyOS CLI commands to devices via NAPALM/SSH.

## Tech Stack

- **Backend:** Python 3.12+ / Flask / Waitress (WSGI)
- **Databases:** MongoDB (firewall configs via PyMongo) + SQLite (user auth via Flask-SQLAlchemy)
- **Auth:** Flask-Login + Flask-Bcrypt
- **Network:** NAPALM 5.1.0 + napalm-vyos + Paramiko for device connectivity
- **Frontend:** Jinja2 templates + jQuery + CSS Grid/Flexbox
- **Package Manager:** uv (with uv.lock for deterministic builds)
- **Container:** Docker (Ubuntu 24.04 base, multi-arch ARM64/AMD64)

## Build & Development Commands

```bash
# Run locally (debug mode when FLASK_ENV=Development in .env)
python app.py

# Run tests
pytest

# Run security scan
bandit -c pyproject.toml -r .

# Docker builds (run bandit + pytest first, then buildx)
make local    # Local Docker image only
make dev      # Push to internal registry
make pubdev   # Push dev build to Docker Hub
make prod     # Push production build to Docker Hub

# Install dependencies
uv sync
```

## Architecture

### Application Entry Point

`app.py` (~1880 lines) is the monolithic Flask application. It defines:
- All route handlers (40+ endpoints)
- The SQLAlchemy User model
- Flask app initialization, login manager, bcrypt setup
- Logging configuration (file + console)

### Package Modules (`package/`)

Each module handles a specific domain. Routes in `app.py` delegate to these functions:

| Module | Purpose |
|--------|---------|
| `auth_functions.py` | Login, registration, password change, version checking |
| `data_file_functions.py` | MongoDB CRUD, backups (local + S3), file uploads, snapshots |
| `chain_functions.py` | Chain and chain rule management (add/delete/reorder) |
| `filter_functions.py` | Filter and filter rule management (parallel to chains) |
| `group_funtions.py` | Address/network/port/domain/MAC/interface groups |
| `interface_functions.py` | Network interface management |
| `flowtable_functions.py` | Flowtable configuration |
| `generate_config.py` | Converts data structures to VyOS CLI commands |
| `napalm_ssh_functions.py` | SSH connectivity, config push, diffs, operational commands |
| `diff_functions.py` | Configuration diff generation |
| `mongo_converter.py` | Legacy JSON-to-MongoDB migration (runs on first startup) |
| `telemetry_functions.py` | Anonymous usage telemetry |

Note: `group_funtions.py` has a typo in the filename — this is intentional/historical.

### Data Flow

```
HTTP Request → Flask route (app.py) → package function
  → read_user_data_file() [MongoDB read]
  → process/modify data
  → write_user_data_file() [MongoDB write]
  → render template or redirect
```

### Data Storage

- **MongoDB:** One collection per user/firewall config. Documents contain complete firewall configuration (chains, filters, groups, etc.) with IPv4/IPv6 root keys.
- **SQLite:** `data/database/auth.db` — user table (id, username, email, hashed_password).
- **Filesystem:** `data/[username]/` directories for per-user config references; `data/log/app.log` for logs; `data/mongo_dumps/` for backups.

### Session State

Flask session stores `data_dir`, `firewall_name`, and `username`. Each user has isolated data directories under `data/`.

### Environment Configuration

Configured via `.env` file (loaded by python-dotenv). Key variables:
- `FLASK_ENV` — "Development" (debug) or "Production"
- `MONGODB_URI` / `MONGODB_DATABASE` — MongoDB connection
- `APP_SECRET_KEY` — Flask session secret
- `SESSION_TIMEOUT` — Minutes (default 120)
- `DISABLE_REGISTRATION` — Boolean to lock out new users
- `LOG_LEVEL` — DEBUG, INFO, WARNING, ERROR
- `BUCKET_NAME`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` — S3 backup config

### Deployment

- **Docker Compose (basic):** `docker/docker-compose.basic.yml` — FW-GUI + MongoDB
- **Docker Compose (recommended):** `docker/docker-compose.recommended.yml` — adds Nginx Proxy Manager + MariaDB
- **Kubernetes:** Helm chart in `chart/fw-gui/`
- **Container runs as** `www-data` on port 8080, data volume at `/opt/fw-gui/data`

## Testing

Tests live in `tests/` and use pytest with mongomock for MongoDB mocking. Run a single test file with:

```bash
pytest tests/test_auth_functions.py
```

Pytest configuration is in `pyproject.toml` (`-v -ra -q` flags).

## Version Management

Version is set in `pyproject.toml` under `[project] version`. The build script reads it and writes `v{VERSION}` to `.version`. Update `pyproject.toml` when bumping versions.
