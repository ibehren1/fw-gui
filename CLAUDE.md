# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FW-GUI is a Flask web application for visually creating and managing VyOS firewall configurations. Users create firewall chains, filters, groups, interfaces, and flowtables through web forms, then push generated VyOS CLI commands to devices via NAPALM/SSH.

## Tech Stack

- **Backend:** Python 3.12+ / Flask / Waitress (WSGI)
- **Database:** MongoDB via PyMongo — firewall configs, user accounts (`users`), encrypted SSH keys (`keys`), the telemetry instance id (`instance`), and server-side sessions (all as of 2.5.0)
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
- Flask app initialization, login manager, bcrypt setup
- Logging configuration (file + console)

### Package Modules (`package/`)

Each module handles a specific domain. Routes in `app.py` delegate to these functions:

| Module | Purpose |
|--------|---------|
| `auth_functions.py` | Login, registration, password change, version checking |
| `user_store.py` | MongoDB `users` collection: account lookup/create, password set, Flask-Login `User` |
| `user_migration.py` | One-shot pre-2.5.0 SQLite `auth.db` → MongoDB account migration (runs at startup) |
| `instance_id.py` | MongoDB `instance` collection: telemetry instance id, incl. adoption of the pre-2.5.0 `instance.id` file |
| `ssh_key_store.py` | MongoDB `keys` collection: Fernet-encrypted SSH keys, decrypt-and-stage, adoption of pre-2.5.0 `.key` files |
| `data_file_functions.py` | MongoDB CRUD, backups (local + S3), file uploads, snapshots |
| `backup_scheduler.py` | Automatic weekly full backup: schedule document in the `instance` collection, atomic run claim, daemon thread, retention pruning |
| `chain_functions.py` | Chain and chain rule management (add/delete/reorder) |
| `filter_functions.py` | Filter and filter rule management (parallel to chains) |
| `rule_order_functions.py` | Shared rule renumbering logic (move up/down, renumber, resequence) used by chains and filters |
| `group_funtions.py` | Address/network/port/domain/MAC/interface groups |
| `interface_functions.py` | Network interface management |
| `flowtable_functions.py` | Flowtable configuration |
| `generate_config.py` | Converts data structures to VyOS CLI commands |
| `napalm_ssh_functions.py` | SSH connectivity, config push, diffs, operational commands |
| `diff_functions.py` | Configuration diff generation |
| `mongo_converter.py` | Legacy pre-1.4.0 JSON-to-MongoDB config migration (runs at startup) |
| `telemetry_functions.py` | Anonymous usage telemetry (UUID + version only; never raises, so it cannot break a config push) |

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
- **MongoDB `users` collection:** one document per account, `_id` = username, fields `email`, `password` (bcrypt hash, str), `disabled`. Accounts are disabled, never deleted — deleting one frees the username, and the next registrant would inherit that username's collection and `data/<username>` directory. Pre-2.5.0 this was SQLite (`data/database/auth.db`); an upgraded install retains it as `auth.db.migrated` for rollback only.
- **MongoDB `instance` collection:** two fixed documents. `{_id: "instance_id", value: <uuid4>}` holds the anonymous telemetry id — pre-2.5.0 this was `data/database/instance.id`; the value is adopted on upgrade and the file retired as `instance.id.migrated`. `{_id: "backup_schedule", ...}` holds the automatic weekly backup's **entire configuration and state** (`enabled`, `day_of_week`, `hour`, `retention`, `poll_seconds`, `lease_seconds`, `next_run`, the claim fields and the last result) — there are no environment variables for it. The schedule shares this collection deliberately: a username is also a collection name, so a new collection would mean reserving another username. `users`, `sessions`, `instance` and `keys` are all rejected as usernames for that reason.
- **MongoDB `keys` collection:** one document per SSH key, `_id` = `"<user>/<name>"`, ciphertext as BSON Binary. The Fernet key is generated at upload, shown to the user once and **never stored**, so the server holds a blob it cannot read. Decrypted keys are staged in the system temp dir, never under `data/`.
- **Filesystem:** outputs only as of 2.5.0 — `data/log/app.log`, `data/backups/`, `data/mongo_dumps/` — plus retained pre-2.5.0 artifacts (`auth.db.migrated`, `instance.id.migrated`, `*.key.migrated`). No durable state and no secrets.

### Session State

Flask session stores `data_dir`, `firewall_name`, and `username`. Each user has isolated data directories under `data/`.

### Environment Configuration

Configured via `.env` file (loaded by python-dotenv). Key variables:
- `FLASK_ENV` — "Development" (debug) or "Production"
- `MONGODB_URI` / `MONGODB_DATABASE` — MongoDB connection (`MONGODB_DATABASE` defaults to `fwgui_database`)
- `MONGODB_USERS_COLLECTION` — Collection holding accounts (default `users`)
- `FWGUI_INSTANCE_ID` — Pins the telemetry instance id instead of reading it from MongoDB; used by CI
- `APP_SECRET_KEY` — Flask session secret
- `SESSION_TIMEOUT` — Minutes (default 120)
- `DISABLE_REGISTRATION` — Boolean to lock out new users
- `LOG_LEVEL` — DEBUG, INFO, WARNING, ERROR
- `BUCKET_NAME`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` — S3 backup config

The automatic weekly backup has **no environment variables** — enabled state, day, hour, retention, poll interval and claim lease all live on the `backup_schedule` document and are edited on the Admin Settings page. One source of truth on purpose: an env var and a stored value that disagreed would need a precedence rule, and whichever lost would look like a bug.

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
