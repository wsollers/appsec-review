"""Cell-local evidence labels (``review-protocol/2``, docs/architecture/review-protocol-v2.md section 4.2).

A label is a short handle (``L1``, ``K2``, ``G1``, ``Q7``) for one logical identity the cell can see. Package
labels are assigned by the application when it builds a cell's package view; ``Q`` labels are added, in
arrival order, for every identity a retrieval turn returns. Labels exist only inside one cell: the ledger
stores the resolved identities, never the labels, and a label from another cell does not resolve here.

The table is the only thing that turns a model's citation into an identity. A raw identity is accepted
wherever a label is, provided the cell received it (it is in the package or in this cell's own retrieval
transcript).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import re
from typing import Any

LABEL = re.compile(r"^[A-Z][0-9]{1,4}$")
LOGICAL_ID = re.compile(r"^asr:[a-z][a-z0-9_]*:[0-9a-f]{64}$")
RETRIEVAL_PREFIX = "Q"
PACKAGE_LETTERS = {"lead": "L", "source": "S", "sink": "K", "range": "R", "guard": "G", "call_site": "F",
                   "path": "P", "entry": "E", "memory": "M", "corroboration": "C", "build": "B", "tag": "T",
                   "gap": "X", "other": "O", "affected": "A",
                   "judge": "J"}                 # a row one of two sides cited, re-presented to a judge


class LabelTable:
    """label -> identity for one cell, extended by retrieval turns."""

    def __init__(self, labels: Mapping[str, str], known: Iterable[str] = (), texts: Mapping[str, str] | None = None):
        self._texts: dict[str, str] = dict(texts or {})        # labels that name a gap, not an identity (X)
        self._labels: dict[str, str] = dict(labels)
        self._by_ref: dict[str, str] = {}
        for label, ref in self._labels.items():
            self._by_ref.setdefault(ref, label)
        self._known = set(known) | set(self._labels.values())
        self._retrieved = 0

    @property
    def labels(self) -> Mapping[str, str]:
        return dict(self._labels)

    @property
    def retrieved(self) -> Mapping[str, str]:
        """The ``Q`` labels this cell's retrieval added, in arrival order."""
        return {label: ref for label, ref in self._labels.items() if label.startswith(RETRIEVAL_PREFIX)}

    def know(self, refs: Iterable[str]) -> None:
        """Mark identities the cell has received, so a raw identity citation of them resolves."""
        self._known.update(ref for ref in refs if isinstance(ref, str))

    def add_package_label(self, label: str, ref: str) -> None:
        if label in self._labels and self._labels[label] != ref:
            raise ValueError(f"label {label} is already assigned")
        self._labels[label] = ref
        self._by_ref.setdefault(ref, label)
        self._known.add(ref)

    def label_for(self, ref: str) -> str | None:
        return self._by_ref.get(ref)

    def add_retrieved(self, ref: str) -> str:
        """The label of a returned identity: its existing label, else the next ``Q`` label."""
        existing = self._by_ref.get(ref)
        if existing is not None:
            return existing
        self._retrieved += 1
        label = f"{RETRIEVAL_PREFIX}{self._retrieved}"
        self._labels[label] = ref
        self._by_ref[ref] = label
        self._known.add(ref)
        return label

    def resolve(self, token: Any) -> str | None:
        """The identity a label or a received raw identity names; ``None`` when it resolves to nothing."""
        if not isinstance(token, str):
            return None
        if LABEL.fullmatch(token):
            return self._labels.get(token)
        if LOGICAL_ID.fullmatch(token) and token in self._known:
            return token
        return None

    def text_of(self, token: Any) -> str | None:
        """The material-gap text an ``X`` label names; ``None`` for any other token."""
        return self._texts.get(token) if isinstance(token, str) else None

    def resolve_all(self, tokens: Iterable[Any]) -> tuple[list[str], list[str]]:
        """(distinct identities in order, tokens that did not resolve)."""
        found: list[str] = []
        dropped: list[str] = []
        for token in tokens:
            ref = self.resolve(token)
            if ref is None:
                dropped.append(str(token)[:80])
            elif ref not in found:
                found.append(ref)
        return found, dropped


__all__ = ["LABEL", "LOGICAL_ID", "LabelTable", "PACKAGE_LETTERS", "RETRIEVAL_PREFIX"]
