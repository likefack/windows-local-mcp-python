"""監査 DB の既存 SQL とトランザクション境界だけを計測する接続。"""

from __future__ import annotations

import sqlite3

from .performance_trace import phase, timed_phase


class TimedAuditConnection(sqlite3.Connection):
    """SQL 本文・引数を記録せず、SQLite 本来の確定・取消し順序を維持する。"""

    @timed_phase("audit_sql_execute")
    def execute(self, *args, **kwargs):
        return super().execute(*args, **kwargs)

    @timed_phase("audit_sql_execute")
    def executemany(self, *args, **kwargs):
        return super().executemany(*args, **kwargs)

    @timed_phase("audit_sql_execute")
    def executescript(self, *args, **kwargs):
        return super().executescript(*args, **kwargs)

    def commit(self):
        if not self.in_transaction:
            return super().commit()
        with phase("audit_commit"):
            return super().commit()

    def rollback(self):
        if not self.in_transaction:
            return super().rollback()
        with phase("audit_rollback"):
            return super().rollback()

    def __exit__(self, exc_type, exc_value, traceback):
        if not self.in_transaction:
            return super().__exit__(exc_type, exc_value, traceback)
        # __exit__ に任せることで、commit 失敗時の SQLite の rollback も保持する。
        with phase("audit_rollback" if exc_type is not None else "audit_commit"):
            return super().__exit__(exc_type, exc_value, traceback)
