"""Signature matching engine.

Takes a decoded packet (src/dst/ports/proto/payload) and returns the rules that
fire. Rules are bucketed by protocol so each packet only checks relevant rules.
"""
from __future__ import annotations

from collections import defaultdict

from .rules import Rule, RuleSet


class Engine:
    def __init__(self, ruleset: RuleSet):
        self.ruleset = ruleset
        self._by_proto: dict[str, list[Rule]] = defaultdict(list)
        for rule in ruleset.rules:
            self._by_proto[rule.protocol].append(rule)

    @property
    def rule_count(self) -> int:
        return len(self.ruleset)

    def _candidate_rules(self, proto: str) -> list[Rule]:
        # rules declared "any" always apply, plus the protocol-specific bucket
        return self._by_proto.get(proto, []) + self._by_proto.get("any", []) + (
            self._by_proto.get("ip", []) if proto in {"tcp", "udp", "icmp"} else []
        )

    def evaluate(
        self,
        proto: str,
        sport: int | None,
        dport: int | None,
        payload: bytes,
    ) -> list[Rule]:
        """Return all rules that match this packet."""
        hits: list[Rule] = []
        for rule in self._candidate_rules(proto):
            if rule.src_port is not None and rule.src_port != sport:
                continue
            if rule.dst_port is not None and rule.dst_port != dport:
                continue
            # header-only rules (no content) require at least a port/proto narrowing
            # to avoid firing on every packet.
            if not rule.has_payload_condition():
                if rule.src_port is None and rule.dst_port is None:
                    continue
                hits.append(rule)
                continue
            if payload and rule.matches_payload(payload):
                hits.append(rule)
        return hits
