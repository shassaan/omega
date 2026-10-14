# Mental model: database rules

These rules are enforced by `hooks/prod_guard.py` (shell), `hooks/ship_readiness.py` (Database
tier, stdlib migration lint), `hooks/lib/redaction.py` (PII) and the contract gate (migrations are
always a non-trivial change). The agent reads them so it stops being surprised.

## Migrations: expand, then contract

A migration must keep the previous application version working while it deploys (rolling deploys
run old and new code against one schema).

| operation | verdict | do this instead |
|---|---|---|
| `DROP COLUMN`, `DROP TABLE`, `TRUNCATE` | high → FAIL | stop reading the column in release N, drop it in release N+1 after a backfill check |
| `ADD COLUMN … NOT NULL` without `DEFAULT` | high → FAIL | add nullable (or with a default), backfill, then `SET NOT NULL` in a later migration |
| `RENAME COLUMN`, `RENAME TO` (table) | high → FAIL | add the new name, dual-write, backfill, switch readers, drop the old name later |
| `ALTER COLUMN … SET NOT NULL`, `nullable=False` | medium → noted | backfill first; verify no NULLs in a pre-check |
| `ALTER COLUMN … TYPE` | medium → noted | new column + backfill for large tables |
| `CREATE INDEX` without `CONCURRENTLY` | medium → noted | `CREATE INDEX CONCURRENTLY` outside a transaction (Alembic: `op.execute` with `autocommit_block`) |

A high finding passes only with an explicit waiver in the migration file:
`-- omega:allow destructive (<reason>)` (SQL) or `# omega:allow destructive (<reason>)`
(Python). The reason is read by the human at contract sign-off, because migration paths are in
`contracts.nontrivial.always_globs`.

Rules of the directory: migration files are append-only (never edit a migration that has shipped;
write a new one); one head (`alembic heads` must list exactly one; Prisma migrations folders are
timestamp-ordered); every migration has a down path or an explicit `-- no-down: <reason>`; the
migration file name says what it does (`0007_add_users_locale_nullable.py`).

What the agent may run locally: `alembic revision`, `alembic upgrade head`, `alembic heads/
current/history/check`, `prisma generate/validate/format`, `prisma migrate status/diff`. What it
may not run: `alembic downgrade`, `alembic stamp`, `prisma migrate reset/deploy/dev/resolve`,
`prisma db push/execute/seed`, `rails db:drop|reset|rollback`, `manage.py flush`, any `DROP`,
`TRUNCATE`, `DELETE`/`UPDATE` without `WHERE`, `GRANT`/`REVOKE`, `dropdb`, `pg_restore`.

## Schema isolation

- One database role per purpose: `app` (DML on application schemas only, no DDL), `migrator`
  (DDL, used only by the deploy step), `readonly` (analytics, dbt sources). The application never
  connects as a superuser or as `migrator`.
- Tenant isolation is explicit: either a `tenant_id` column on every tenant-scoped table with
  row-level security policies (`policies/**` is a detected Analytics-tier directory), or one schema
  per tenant. Mixed strategies are a contract-level decision and need sign-off.
- Analytics (dbt) reads from `raw`/`bronze` schemas populated by extraction, never from the
  application's live tables, and writes only to `analytics_*` schemas. Gold models never
  `select *` from raw.
- Local development uses a local database (`localhost`, `127.0.0.1`, a docker service name).
  `prod_guard` denies mutating SQL and migration commands against anything else by refusing
  unresolvable hosts. There are no production credentials in the agent's environment; that is the
  boundary that holds when a guard is bypassed.

## Zero PII

- PII never enters: logs, the change ledger, job outputs, clearance files, PR bodies, Slack
  messages, test fixtures, seed data, dbt seeds, screenshots, or the agent's transcript on purpose.
  `redaction.redact` runs at every one of those boundaries; `review.json.pii_scan` fails a Stop
  when an email, SSN, Luhn-valid card number, mod-97-valid IBAN or formatted phone number appears
  in code, SQL, docs or config outside `tests/fixtures/**` and `*.example` files.
- Fixtures use `@example.com` addresses, `555-01xx` phone numbers, `AKIAIOSFODNN7EXAMPLE`-style
  dummies and synthetic names. Real exports are never checked in.
- Columns that hold PII are tagged in the schema source of truth (`meta: {pii: true}` in dbt
  `schema.yml`; a `# pii` trailing comment in SQL DDL; `/// @pii` doc comment in Prisma) so the
  Analytics tier can verify that gold models either exclude or hash them.
- Secrets are not PII but follow the same path: never in code, never in a URL, never in argv.
  `DATABASE_URL` passwords are redacted at the password segment only, so the host and database
  name stay debuggable.
- Deletion requests must be implementable: every table with PII has a documented path from a
  user id to its rows (the Journey seam of the contract that introduced the table must include a
  deletion scenario).
