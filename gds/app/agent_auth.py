from __future__ import annotations

import hmac
import json
import os
import threading
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentPolicy:
    token: str
    allow_trust_anchor: bool
    allowed_trustlists: set[tuple[str, str]]
    allowed_applications: set[str]
    owned_applications: set[str]


class AgentAuthStore:
    def __init__(self, tokens_file: str):
        self._tokens_file = tokens_file
        self._lock = threading.Lock()
        self._cached_mtime: float | None = None
        self._cached_policies: dict[str, AgentPolicy] = {}

    def get_policy(self, agent_id: str) -> AgentPolicy | None:
        policies = self._load_policies()
        return policies.get(agent_id)

    def _load_policies(self) -> dict[str, AgentPolicy]:
        with self._lock:
            try:
                mtime = os.path.getmtime(self._tokens_file)
            except FileNotFoundError:
                self._cached_mtime = None
                self._cached_policies = {}
                return {}

            if self._cached_mtime is not None and mtime == self._cached_mtime:
                return self._cached_policies

            with open(self._tokens_file, "r", encoding="utf-8") as f:
                raw = json.load(f)

            policies = _parse_policies(raw)
            self._cached_mtime = mtime
            self._cached_policies = policies
            return policies


def _parse_policies(payload: Any) -> dict[str, AgentPolicy]:
    if not isinstance(payload, dict):
        return {}

    agents_raw = payload.get("agents")
    if isinstance(agents_raw, dict):
        source = agents_raw
    else:
        source = payload

    out: dict[str, AgentPolicy] = {}
    for agent_id, policy_raw in source.items():
        if not isinstance(agent_id, str) or not agent_id.strip():
            continue
        parsed = _parse_single_policy(policy_raw)
        if parsed:
            out[agent_id.strip()] = parsed
    return out


def _parse_single_policy(policy_raw: Any) -> AgentPolicy | None:
    if isinstance(policy_raw, str):
        token = policy_raw.strip()
        if not token:
            return None
        return AgentPolicy(
            token=token,
            allow_trust_anchor=True,
            allowed_trustlists=set(),
            allowed_applications=set(),
            owned_applications=set(),
        )

    if not isinstance(policy_raw, dict):
        return None

    token = str(policy_raw.get("token", "")).strip()
    if not token:
        return None

    allow_trust_anchor = bool(policy_raw.get("allow_trust_anchor", True))
    allowed_trustlists = _parse_allowed_trustlists(policy_raw.get("allowed_trustlists", []))
    allowed_applications = _parse_allowed_applications(policy_raw.get("allowed_applications", []))
    owned_applications = _parse_allowed_applications(policy_raw.get("owned_applications", []))
    return AgentPolicy(
        token=token,
        allow_trust_anchor=allow_trust_anchor,
        allowed_trustlists=allowed_trustlists,
        allowed_applications=allowed_applications,
        owned_applications=owned_applications,
    )


def _parse_allowed_trustlists(value: Any) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    if not isinstance(value, list):
        return out

    for item in value:
        if isinstance(item, str):
            parts = item.split(":")
            if len(parts) == 2:
                out.add((parts[0].strip(), parts[1].strip()))
            continue
        if isinstance(item, dict):
            zone = str(item.get("zone", "")).strip()
            role = str(item.get("role", "")).strip()
            if zone and role:
                out.add((zone, role))
    return out


def _parse_allowed_applications(value: Any) -> set[str]:
    out: set[str] = set()
    if not isinstance(value, list):
        return out
    for item in value:
        if isinstance(item, str) and item.strip():
            out.add(item.strip())
    return out


def verify_token(policy: AgentPolicy, provided_token: str) -> bool:
    return hmac.compare_digest(policy.token, provided_token)
