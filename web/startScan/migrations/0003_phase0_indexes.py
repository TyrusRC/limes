"""Phase 0 indexes, built concurrently and safe to re-run.

CREATE INDEX CONCURRENTLY leaves an INVALID index if interrupted, and a plain
re-run would fail with "already exists". Each index is therefore dropped first
if invalid, then created IF NOT EXISTS. State ops keep makemigrations in sync.
"""
from django.db import migrations, models

INDEXES = [
    ('subdomain', 'sub_scan_disc_idx', ['scan_history', 'discovered_date']),
    ('subdomain', 'sub_scan_status_idx', ['scan_history', 'http_status']),
    ('endpoint', 'ep_scan_disc_idx', ['scan_history', 'discovered_date']),
    ('endpoint', 'ep_scan_status_idx', ['scan_history', 'http_status']),
    ('vulnerability', 'vuln_scan_sev_idx', ['scan_history', 'severity']),
    ('vulnerability', 'vuln_scan_disc_idx', ['scan_history', 'discovered_date']),
    ('scanactivity', 'act_scan_time_idx', ['scan_of', 'time']),
    ('scanactivity', 'act_scan_status_idx', ['scan_of', 'status']),
    ('scanhistory', 'scan_status_idx', ['scan_status']),
    ('scanhistory', 'scan_domain_start_idx', ['domain', 'start_scan_date']),
]

DROP_INVALID = (
    "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_index i ON i.indexrelid=c.oid "
    "WHERE c.relname='{name}' AND NOT i.indisvalid) THEN EXECUTE 'DROP INDEX {name}'; "
    "END IF; END $$;"
)


def _op(model, name, fields):
    # Columns are FK/plain fields; FKs are stored as <field>_id.
    cols = ', '.join(f'"{f}_id"' if f in FK_FIELDS else f'"{f}"' for f in fields)
    return migrations.SeparateDatabaseAndState(
        database_operations=[
            migrations.RunSQL(DROP_INVALID.format(name=name), migrations.RunSQL.noop),
            migrations.RunSQL(
                f'CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON "startScan_{model}" ({cols});',
                f'DROP INDEX IF EXISTS {name};'),
        ],
        state_operations=[migrations.AddIndex(model, models.Index(fields=fields, name=name))],
    )


FK_FIELDS = {'scan_history', 'scan_of', 'domain'}


class Migration(migrations.Migration):
    atomic = False
    dependencies = [('startScan', '0002_auto_20240911_0145')]

    operations = [_op(*i) for i in INDEXES]
