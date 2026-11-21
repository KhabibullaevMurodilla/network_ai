"""A generic, multi-table fake Supabase client for security/adversarial
tests that need real multi-tenant state (two real tenants, real rows,
real cross-tenant ID guesses) rather than the single-purpose FakeDB each
other test file hand-rolls. Supports the subset of the supabase-py query
builder this codebase actually uses: insert/update/delete/select, eq/in_/
is_/not_/gte, order/limit, single(), execute().

This is intentionally a plain in-memory store, not a mock framework --
real filtering logic (not a mocked "whatever you ask for" response) is the
point: a test asserting "tenant B cannot read tenant A's row" has to run
through the same .eq("tenant_id", ...) filtering the real app code issues,
or it isn't testing anything.
"""
from __future__ import annotations
import itertools
from datetime import datetime, timezone

_id_counter = itertools.count(1)

# Tables whose real Postgres schema (supabase/schema.sql) gives created_at a
# `default now()` -- every row written through the real client always has
# one, whether or not the INSERT statement mentioned it. This fake mirrored
# that for every OTHER column default (id via _id_counter) but not this one,
# so code that reads back a freshly-inserted row and assumes created_at is
# always present (true in production) could KeyError/crash against this
# harness alone. insert() below closes that gap the same way select(...,
# count="exact") was closed: make the fake match what Postgres actually
# does, rather than special-casing every caller.
_CREATED_AT_TABLES = {
    "tenants", "profiles", "api_keys", "telemetry_flows", "anomaly_events",
    "ot_protocol_events", "audit_log", "webhook_configs", "incidents",
    "entity_suppressions", "response_actions",
}


def _eq(actual, val) -> bool:
    """PostgREST sends every filter value as text in the query string and
    Postgres casts it to the column type, so eq("id", "7") matches an
    integer id 7 in production. Mirror that: exact match first, else
    compare as strings (never for None, which must stay NULL-semantics)."""
    if actual == val:
        return True
    if actual is None or val is None:
        return False
    return str(actual) == str(val)


class FakeResult:
    def __init__(self, data, count=None):
        self.data = data
        self.count = count


class FakeQuery:
    def __init__(self, store: dict, name: str):
        self.store = store
        self.name = name
        self.table = store.setdefault(name, [])
        self._mode = None
        self._filters: list[tuple[str, str, object]] = []  # (field, op, value)
        self._order = None
        self._limit = None
        self._single = False
        self._count_requested = False

    # --- building ---
    def insert(self, rows):
        self._mode = "insert"
        self._rows = rows if isinstance(rows, list) else [rows]
        return self

    def update(self, data):
        self._mode = "update"
        self._update_data = data
        return self

    def delete(self):
        self._mode = "delete"
        return self

    def select(self, *a, **k):
        if self._mode is None:
            self._mode = "select"
        # supabase-py's select(..., count="exact") -- mirrored here (count
        # of matched rows, computed at execute() time) so code written
        # against the real client's row-count pattern is still testable
        # against this fake without rewriting it to select()+len().
        self._count_requested = k.get("count") is not None
        return self

    def eq(self, field, val):
        self._filters.append((field, "eq", val))
        return self

    def in_(self, field, vals):
        self._filters.append((field, "in", list(vals)))
        return self

    def gte(self, field, val):
        self._filters.append((field, "gte", val))
        return self

    def lte(self, field, val):
        self._filters.append((field, "lte", val))
        return self

    def is_(self, field, val):
        self._filters.append((field, "is", val))
        return self

    @property
    def not_(self):
        return _NotProxy(self)

    def order(self, field, desc=False):
        self._order = (field, desc)
        return self

    def limit(self, n):
        self._limit = n
        return self

    def single(self):
        self._single = True
        return self

    # --- matching ---
    def _row_matches(self, row: dict) -> bool:
        for field, op, val in self._filters:
            actual = row.get(field)
            if op == "eq" and not _eq(actual, val):
                return False
            if op == "in" and actual not in val:
                return False
            if op == "gte" and (actual is None or actual < val):
                return False
            if op == "lte" and (actual is None or actual > val):
                return False
            if op == "is":
                is_null = val in (None, "null")
                if is_null and actual is not None:
                    return False
                if not is_null and actual is None:
                    return False
            if op == "not_is":
                is_null = val in (None, "null")
                if is_null and actual is None:
                    return False
                if not is_null and actual is not None:
                    return False
        return True

    def execute(self):
        if self._mode == "insert":
            out = []
            for r in self._rows:
                row = dict(r)
                row.setdefault("id", next(_id_counter))
                if self.name in _CREATED_AT_TABLES:
                    row.setdefault("created_at", datetime.now(timezone.utc).isoformat())
                self.table.append(row)
                out.append(row)
            return FakeResult(out)

        matches = [r for r in self.table if self._row_matches(r)]

        if self._mode == "update":
            for r in matches:
                r.update(self._update_data)
            return FakeResult(matches)

        if self._mode == "delete":
            for r in matches:
                self.table.remove(r)
            return FakeResult(matches)

        # select
        count = len(matches) if self._count_requested else None
        if self._order:
            field, desc = self._order
            matches = sorted(matches, key=lambda r: (r.get(field) is None, r.get(field)), reverse=desc)
        if self._limit is not None:
            matches = matches[: self._limit]
        if self._single:
            return FakeResult(matches[0] if matches else None, count=count)
        return FakeResult(matches, count=count)


class _NotProxy:
    """Supports the .not_.is_(...) chain used in a few routers."""
    def __init__(self, query: FakeQuery):
        self._query = query

    def is_(self, field, val):
        self._query._filters.append((field, "not_is", val))
        return self._query


class FakeDB:
    def __init__(self):
        self._store: dict[str, list[dict]] = {}

    def table(self, name: str) -> FakeQuery:
        return FakeQuery(self._store, name)

    def seed(self, name: str, rows: list[dict]):
        self._store.setdefault(name, []).extend(dict(r) for r in rows)
