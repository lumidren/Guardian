"""
SQLite persistence store for auto-learned policy rules and user decisions (Task 56).
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from .models import DecisionMode, PolicyRule, RuleKind, RuleScope, RuleSource


class PolicySQLiteStore:
    """Task 56: SQLite database backing store for `policy_rules` and `policy_decisions` tables."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_rules (
                rule_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                scope TEXT NOT NULL,
                target_id TEXT NOT NULL,
                source TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_decisions (
                decision_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                rule_kind TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                mode TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL
            )
            """
        )
        self._conn.commit()

    def upsert_rule(self, rule: PolicyRule) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO policy_rules
            (rule_id, kind, scope, target_id, source, parameters_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule.rule_id,
                str(rule.kind),
                str(rule.scope),
                rule.target_id,
                str(rule.source),
                json.dumps(rule.parameters),
                rule.created_at,
                rule.expires_at,
            ),
        )
        self._conn.commit()

    def get_active_rules(self, target_id: str | None = None, now: float | None = None) -> list[PolicyRule]:
        current = time.time() if now is None else now
        query = "SELECT * FROM policy_rules"
        params: tuple[Any, ...] = ()
        if target_id is not None:
            query += " WHERE target_id = ?"
            params = (target_id,)
        rows = self._conn.execute(query, params).fetchall()
        out: list[PolicyRule] = []
        for r in rows:
            rule = PolicyRule(
                rule_id=str(r["rule_id"]),
                kind=RuleKind(str(r["kind"])),
                scope=RuleScope(str(r["scope"])),
                target_id=str(r["target_id"]),
                source=RuleSource(str(r["source"])),
                parameters=json.loads(str(r["parameters_json"])),
                created_at=float(r["created_at"]),
                expires_at=float(r["expires_at"]) if r["expires_at"] is not None else None,
            )
            if not rule.is_expired(current):
                out.append(rule)
        return out

    def record_decision(
        self,
        decision_id: str,
        device_id: str,
        rule_kind: RuleKind,
        subject_key: str,
        mode: DecisionMode,
        created_at: float | None = None,
        expires_at: float | None = None,
    ) -> None:
        ts = time.time() if created_at is None else created_at
        self._conn.execute(
            """
            INSERT OR REPLACE INTO policy_decisions
            (decision_id, device_id, rule_kind, subject_key, mode, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (decision_id, device_id, str(rule_kind), subject_key, str(mode), ts, expires_at),
        )
        self._conn.commit()

    def get_decisions(self, device_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM policy_decisions WHERE device_id = ? ORDER BY created_at ASC",
            (device_id,),
        ).fetchall()
        return [dict(r) for r in rows]
