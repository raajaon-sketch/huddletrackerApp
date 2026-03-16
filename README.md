# Huddle Tracker

## Project Structure (VS Code)

HuddleTrackerApp/
├── app.py                   <- Main Flask application
├── requirements.txt         <- Python dependencies  
├── .env                     <- Environment variables
├── .gitignore
├── huddle_tracker.db        <- SQLite DB (auto-created)
├── templates/
│   ├── login.html
│   ├── dashboard.html
│   └── task_names.html
├── static/
│   ├── css/
│   └── js/
└── .vscode/
    ├── launch.json          <- Press F5 to run
    ├── settings.json
    └── extensions.json

## Setup

1. Open folder in VS Code: File > Open Folder > HuddleTrackerApp
2. Install deps: pip install -r requirements.txt
3. Run: Press F5  OR  python app.py
4. Open: http://127.0.0.1:5000

## Login
admin    / Admin@1234
lead1    / Lead@1234
member1  / Member@1234

## Pages
/             -> redirects to dashboard
/login        -> login page
/dashboard    -> main dashboard
/task-names   -> Task Names & Cap Timings

## Reset DB
del huddle_tracker.db
python app.py

## v26 Upgrade — What's New

### ✅ Horizon 1: Quick Wins (all complete in v25/v26)
- **Inline editing** — Change status/priority/assignee directly in the table row
- **Bulk action toolbar** — Select multiple tasks; apply status, priority, or assignee in one click
- **URL-persistent filters** — Active filters survive page refresh (stored in query string)
- **Keyboard shortcuts** — N = new task, / = search, K = kanban toggle, R = refresh, Esc = close

### ✅ Horizon 2: Core Upgrades
- **Kanban board** — Drag-and-drop cards between status columns; switch with K or the view toggle
- **Real-time SSE push** — `GET /api/stream` streams task_created / task_updated / task_deleted events to all connected clients; no polling required; auto-reconnects on drop (live indicator in topbar)
- **Audit log** — Every field change on every task is recorded in the `task_audit` table; view the full history on the 🕐 History tab inside any task's detail modal
- **`GET /api/tasks/kanban`** — New endpoint returns tasks grouped by status; supports `?project_id=N`
- **`GET /api/tasks/<id>/audit`** — Returns the immutable change trail for a task (newest first, max 200 rows)
- **Admin portal SSE** — Admin portal also subscribes to the SSE stream so the All Tasks table stays in sync without a manual refresh

### New DB table
`task_audit` — created automatically by `db.create_all()` on first run after upgrade.
  For existing databases: `flask db migrate && flask db upgrade` (requires Flask-Migrate, already in requirements.txt).
