from __future__ import annotations

import sqlite3
from pathlib import Path

for database in sorted(Path('.dev-tmp').rglob('audit.db')):
    print(f'=== {database} ===')
    db = sqlite3.connect(database)
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute(
            'SELECT id,status,error,result_json,worker_pid,child_pid FROM operations ORDER BY created_at'
        ).fetchall()
        for row in rows:
            print(dict(row))
            events = db.execute(
                'SELECT event_type,payload_json FROM events WHERE operation_id=? ORDER BY id',
                (row['id'],),
            ).fetchall()
            for event in events:
                print('  EVENT', event['event_type'], event['payload_json'])
    finally:
        db.close()
