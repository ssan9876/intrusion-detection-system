"""Signature rule model + loader.

A rule is a declarative signature matched against each packet. The format is a
deliberately simple JSON dialect (inspired by Snort but far smaller) so that
new signatures can be added without touching code.

Example rule::

    {
      "id": "MAL-EICAR",
      "name": "EICAR antivirus test string",
      "severity": "high",
      "category": "malware",
      "protocol": "tcp",
      "dst_port": "any",
      "content": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
      "nocase": true,
      "references": ["https://www.eicar.org/"]
    }

Match fields (all optional except id/name):
  protocol    one of tcp/udp/icmp/ip/any   (default any)
  src_port    int | "any"
  dst_port    int | "any"
  content     ASCII substring to find in the payload
  content_hex hex string (e.g. "deadbeef") to find in the payload bytes
  regex       Python regex matched against the payload (text)
  nocase      case-insensitive content/regex match (default false)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass
class Rule:
    id: str
    name: str
    severity: str = "medium"
    category: str = "generic"
    protocol: str = "any"
    src_port: int | None = None
    dst_port: int | None = None
    content: str | None = None
    content_hex: str | None = None
    regex: str | None = None
    nocase: bool = False
    references: list[str] = field(default_factory=list)

    # compiled / derived fields (filled in __post_init__)
    _content_bytes: bytes | None = field(default=None, repr=False)
    _regex: re.Pattern | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.protocol = (self.protocol or "any").lower()
        if self.severity not in SEVERITIES:
            self.severity = "medium"

        if self.content is not None:
            text = self.content
            self._content_bytes = (text.lower() if self.nocase else text).encode("utf-8", "ignore")
        elif self.content_hex is not None:
            self._content_bytes = bytes.fromhex(self.content_hex.replace(" ", ""))

        if self.regex is not None:
            flags = re.IGNORECASE if self.nocase else 0
            self._regex = re.compile(self.regex, flags)

    def matches_payload(self, payload: bytes) -> bool:
        """Return True if this rule's content/hex/regex matches the payload."""
        if self._content_bytes is not None:
            haystack = payload.lower() if (self.nocase and self.content is not None) else payload
            if self._content_bytes not in haystack:
                return False
        if self._regex is not None:
            text = payload.decode("latin-1", "ignore")
            if not self._regex.search(text):
                return False
        # A rule with no payload condition matches on header criteria alone.
        return True

    def has_payload_condition(self) -> bool:
        return self._content_bytes is not None or self._regex is not None


@dataclass
class RuleSet:
    rules: list[Rule]
    source: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> "RuleSet":
        path = Path(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        # Accept either a bare list or {"rules": [...]}
        items = raw["rules"] if isinstance(raw, dict) else raw
        rules: list[Rule] = []
        known = {f for f in Rule.__dataclass_fields__ if not f.startswith("_")}
        for item in items:
            data = {k: v for k, v in item.items() if k in known}
            rules.append(Rule(**data))
        return cls(rules=rules, source=path)

    def __len__(self) -> int:
        return len(self.rules)
