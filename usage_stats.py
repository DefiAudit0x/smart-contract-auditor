import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta


# L-07: retention window for usage_events. 0 disables pruning.
KEEP_DAYS = int(os.environ.get("USAGE_KEEP_DAYS", "90"))


class UsageTracker:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "instance", "usage.db")
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._last_prune = 0.0
        self._create_table()

    def _create_table(self):
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_value TEXT NOT NULL,
                    duration_ms INTEGER DEFAULT 0
                )
                """
            )
            # L-07: get_summary filters on timestamp — without this index the
            # scans slow down as the table grows.
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_usage_events_timestamp ON usage_events(timestamp)"
            )
            self._conn.commit()

    def _prune_old_events(self):
        """L-07: lazily delete events older than the retention window, at
        most once every 24h — the table used to grow forever."""
        if KEEP_DAYS <= 0:
            return
        now = time.monotonic()
        if now - self._last_prune < 86400:
            return
        self._last_prune = now
        cutoff = (datetime.utcnow() - timedelta(days=KEEP_DAYS)).isoformat()
        self._conn.execute("DELETE FROM usage_events WHERE timestamp < ?", (cutoff,))

    def log_event(self, event_type, event_value, duration_ms=0):
        with self._lock:
            self._prune_old_events()
            self._conn.execute(
                "INSERT INTO usage_events (timestamp, event_type, event_value, duration_ms) VALUES (?, ?, ?, ?)",
                (datetime.utcnow().isoformat(), event_type, event_value, duration_ms),
            )
            self._conn.commit()

    def get_summary(self, days=7):
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        with self._lock:
            total = self._conn.execute(
                "SELECT event_type, COUNT(*) FROM usage_events WHERE timestamp >= ? GROUP BY event_type",
                (cutoff,),
            ).fetchall()

            models = self._conn.execute(
                "SELECT event_value, COUNT(*) FROM usage_events WHERE event_type = 'model_used' AND timestamp >= ? GROUP BY event_value ORDER BY COUNT(*) DESC LIMIT 5",
                (cutoff,),
            ).fetchall()

            analyses = self._conn.execute(
                "SELECT event_value, COUNT(*) FROM usage_events WHERE event_type = 'audit_run' AND timestamp >= ? GROUP BY event_value ORDER BY COUNT(*) DESC LIMIT 5",
                (cutoff,),
            ).fetchall()

        return {
            "total_events": sum(r[1] for r in total),
            "by_event_type": dict(total),
            "top_models": dict(models),
            "top_analyses": dict(analyses),
        }

    def get_recent(self, limit=20):
        with self._lock:
            rows = self._conn.execute(
                "SELECT timestamp, event_type, event_value, duration_ms FROM usage_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "timestamp": r[0],
                "event_type": r[1],
                "event_value": r[2],
                "duration_ms": r[3],
            }
            for r in rows
        ]

    def close(self):
        with self._lock:
            self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


_TRACKER = UsageTracker()


def get_tracker():
    return _TRACKER
