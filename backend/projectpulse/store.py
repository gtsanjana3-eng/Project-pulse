"""Persistence layer (stdlib sqlite3, versioned migrations).
SQLAlchemy/PostgreSQL were not installable in the build sandbox. Migration path:
keep this class's public methods as the interface, reimplement them on SQLAlchemy
sessions, and port MIGRATIONS to Alembic revisions (one revision per list entry)."""
import json, sqlite3, threading, uuid, datetime as dt
from .errors import NotFound, BadTransition
from .findings import derive_findings

TRANSITIONS = {"queued": {"running", "failed"}, "running": {"completed", "failed"}, "completed": set(), "failed": set()}
MAX_PAGE = 100
USER_FINDING_STATUSES = {"open", "accepted_risk", "unverified"}
DETAIL_KEYS = ("description", "problem_statement", "target_users", "features", "tech_stack", "repo_url")
JSON_KEYS = ("features", "tech_stack")

MIGRATIONS = [  # index+1 == PRAGMA user_version after applying
"""
CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE projects(id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL, url TEXT NOT NULL,
  description TEXT, problem_statement TEXT, target_users TEXT, features TEXT, tech_stack TEXT, repo_url TEXT, created_at TEXT NOT NULL);
CREATE TABLE audit_runs(id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), owner_id TEXT NOT NULL,
  attempt_no INTEGER NOT NULL, status TEXT NOT NULL, scoring_version TEXT, overall REAL, effective_weights TEXT, report TEXT,
  created_at TEXT NOT NULL, UNIQUE(project_id, attempt_no));
CREATE TABLE category_scores(audit_id TEXT REFERENCES audit_runs(id), category TEXT, score REAL, status TEXT, checks_run INTEGER, confidence TEXT);
CREATE TABLE findings(audit_id TEXT REFERENCES audit_runs(id), key TEXT, title TEXT, category TEXT, severity TEXT, evidence TEXT,
  recommended_fix TEXT, status TEXT, PRIMARY KEY(audit_id, key));
CREATE TABLE presentations(id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit_runs(id), owner_id TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX ix_runs_project ON audit_runs(project_id, attempt_no);
CREATE INDEX ix_projects_owner ON projects(owner_id);
""",
]
now = lambda: dt.datetime.now(dt.timezone.utc).isoformat()

class Store:
    def __init__(self, path=":memory:"):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False); self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        v = self.db.execute("PRAGMA user_version").fetchone()[0]
        for i, sql in enumerate(MIGRATIONS[v:], start=v + 1):
            self.db.executescript(sql); self.db.execute(f"PRAGMA user_version={i}")
        self.db.commit()
    def close(self):
        with self.lock:
            self.db.close()

    # users
    def create_user(self, email, pw_hash):
        uid = str(uuid.uuid4())
        try: self.db.execute("INSERT INTO users VALUES(?,?,?,?)", (uid, email, pw_hash, now())); self.db.commit()
        except sqlite3.IntegrityError: raise ValueError("email exists")
        return uid
    def get_user_by_email(self, email):
        r = self.db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        return dict(r) if r else None

    # projects
    def create_project(self, owner_id, name, url, **details):
        bad = set(details) - set(DETAIL_KEYS)
        if bad: raise ValueError(f"unknown project fields: {sorted(bad)}")
        vals = [json.dumps(details[k]) if k in JSON_KEYS and k in details else details.get(k) for k in DETAIL_KEYS]
        pid = str(uuid.uuid4())
        self.db.execute("INSERT INTO projects VALUES(?,?,?,?,?,?,?,?,?,?,?)", (pid, owner_id, name, url, *vals, now())); self.db.commit()
        return pid
    def _project(self, owner_id, pid):
        r = self.db.execute("SELECT * FROM projects WHERE id=? AND owner_id=?", (pid, owner_id)).fetchone()
        if not r: raise NotFound("project not found")   # same error for missing and foreign: no existence leak
        return r
    def get_project(self, owner_id, pid):
        d = dict(self._project(owner_id, pid))
        for k in JSON_KEYS: d[k] = json.loads(d[k]) if d[k] else []
        d.pop("owner_id"); return d
    def list_projects(self, owner_id, limit=20, offset=0):
        limit = max(1, min(int(limit), MAX_PAGE)); offset = max(0, int(offset))
        ids = [r["id"] for r in self.db.execute("SELECT id FROM projects WHERE owner_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?", (owner_id, limit, offset))]
        total = self.db.execute("SELECT COUNT(*) FROM projects WHERE owner_id=?", (owner_id,)).fetchone()[0]
        return {"total": total, "limit": limit, "offset": offset, "items": [self.get_project(owner_id, i) for i in ids]}
    def count_projects(self, owner_id):
        return self.db.execute("SELECT COUNT(*) FROM projects WHERE owner_id=?", (owner_id,)).fetchone()[0]

    # audits
    def start_audit(self, owner_id, project_id):
        self._project(owner_id, project_id)
        n = self.db.execute("SELECT COALESCE(MAX(attempt_no),0)+1 FROM audit_runs WHERE project_id=?", (project_id,)).fetchone()[0]
        aid = str(uuid.uuid4())
        self.db.execute("INSERT INTO audit_runs(id,project_id,owner_id,attempt_no,status,created_at) VALUES(?,?,?,?,?,?)",
                        (aid, project_id, owner_id, n, "queued", now())); self.db.commit()
        return aid
    def _set_status(self, aid, new):
        cur = self.db.execute("SELECT status FROM audit_runs WHERE id=?", (aid,)).fetchone()
        if not cur: raise NotFound("audit not found")
        if new not in TRANSITIONS[cur["status"]]: raise BadTransition(f'{cur["status"]} -> {new}')
        self.db.execute("UPDATE audit_runs SET status=? WHERE id=?", (new, aid))
    def mark_running(self, aid): self._set_status(aid, "running"); self.db.commit()
    def mark_failed(self, aid, reason):
        self._set_status(aid, "failed")
        self.db.execute("UPDATE audit_runs SET report=? WHERE id=?", (json.dumps({"error": reason}), aid)); self.db.commit()
    def complete_audit(self, aid, report):
        self._set_status(aid, "completed")
        o = report["overall"]
        self.db.execute("UPDATE audit_runs SET scoring_version=?, overall=?, effective_weights=?, report=? WHERE id=?",
                        (o["scoring_version"], o["score"], json.dumps(o["effective_weights"]), json.dumps(report), aid))
        for c in report["categories"]:
            self.db.execute("INSERT INTO category_scores VALUES(?,?,?,?,?,?)", (aid, c["category"], c["score"], c["status"], c["checks_run"], c["confidence"]))
        for f in derive_findings(report["checks"]):
            self.db.execute("INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?)", (aid, f["key"], f["title"], f["category"], f["severity"], f["evidence"], f["recommended_fix"], f["status"]))
        self.db.commit()
    def _audit_row(self, owner_id, aid):
        r = self.db.execute("SELECT * FROM audit_runs WHERE id=? AND owner_id=?", (aid, owner_id)).fetchone()
        if not r: raise NotFound("audit not found")
        return r
    def get_audit(self, owner_id, aid):
        r = self._audit_row(owner_id, aid)
        cats = [dict(x) for x in self.db.execute("SELECT category,score,status,checks_run,confidence FROM category_scores WHERE audit_id=?", (aid,))]
        fnd = [dict(x) for x in self.db.execute("SELECT * FROM findings WHERE audit_id=?", (aid,))]
        return {**{k: r[k] for k in ("id", "project_id", "attempt_no", "status", "scoring_version", "overall", "created_at")},
                "effective_weights": json.loads(r["effective_weights"] or "{}"), "categories": cats, "findings": fnd}
    def get_report(self, owner_id, aid):
        return json.loads(self._audit_row(owner_id, aid)["report"] or "{}")
    def list_audits(self, owner_id, project_id, limit=20, offset=0):
        self._project(owner_id, project_id)
        limit = max(1, min(int(limit), MAX_PAGE)); offset = max(0, int(offset))
        rows = self.db.execute("SELECT id FROM audit_runs WHERE project_id=? ORDER BY attempt_no DESC LIMIT ? OFFSET ?", (project_id, limit, offset)).fetchall()
        total = self.db.execute("SELECT COUNT(*) FROM audit_runs WHERE project_id=?", (project_id,)).fetchone()[0]
        return {"total": total, "limit": limit, "offset": offset, "items": [self.get_audit(owner_id, r["id"]) for r in rows]}
    def count_audits_since(self, owner_id, iso):
        return self.db.execute("SELECT COUNT(*) FROM audit_runs WHERE owner_id=? AND created_at>=?", (owner_id, iso)).fetchone()[0]
    def set_finding_status(self, owner_id, aid, key, status):
        self._audit_row(owner_id, aid)
        if status == "fixed": raise ValueError("'fixed' can only be established by a later audit in which the check passes")
        if status not in USER_FINDING_STATUSES: raise ValueError(f"status must be one of {sorted(USER_FINDING_STATUSES)}")
        cur = self.db.execute("UPDATE findings SET status=? WHERE audit_id=? AND key=?", (status, aid, key))
        if cur.rowcount == 0: raise NotFound("finding not found")
        self.db.commit()

    # presentations
    def save_presentation(self, owner_id, aid, content):
        self._audit_row(owner_id, aid); pid = str(uuid.uuid4())
        self.db.execute("INSERT INTO presentations VALUES(?,?,?,?,?)", (pid, aid, owner_id, json.dumps(content), now())); self.db.commit()
        return pid
    def get_presentation(self, owner_id, pid):
        r = self.db.execute("SELECT * FROM presentations WHERE id=? AND owner_id=?", (pid, owner_id)).fetchone()
        if not r: raise NotFound("presentation not found")
        return {"id": r["id"], "audit_id": r["audit_id"], "created_at": r["created_at"], "content": json.loads(r["content"])}
    def latest_presentation(self, owner_id, aid):
        self._audit_row(owner_id, aid)
        r = self.db.execute("SELECT id FROM presentations WHERE audit_id=? AND owner_id=? ORDER BY created_at DESC LIMIT 1", (aid, owner_id)).fetchone()
        if not r: raise NotFound("presentation not found")
        return self.get_presentation(owner_id, r["id"])

def _locked(fn):
    def w(self, *a, **k):
        with self.lock: return fn(self, *a, **k)
    w.__name__ = fn.__name__; return w
for _n, _f in list(vars(Store).items()):
    if callable(_f) and not _n.startswith("_"): setattr(Store, _n, _locked(_f))
