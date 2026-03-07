# SecurityClaw Web UI

React/Vite frontend and FastAPI backend for the SecurityClaw service console.

## Commands

From the project root:

- `python main.py web-build` — install frontend dependencies and build the production UI
- `python main.py web-dev` — run the Vite frontend in development mode
- `python main.py service` — start the combined API + UI + scheduler service
- `python main.py service --api-only` — start the API/UI without scheduled jobs

## Structure

- `web/api` — FastAPI backend used by `main.py service`
- `web/src` — React frontend source
- `web/dist` — built frontend output served by Python in production

## Notes

- Secrets remain in `.env` and are masked in the UI.
- Skill schedules are read from `instruction.md` frontmatter.
- Skill manifests and instructions are editable from the web UI.
