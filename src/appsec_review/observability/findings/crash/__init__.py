"""Crash reports as independent evidence about findings (finding-metrics.md section 7, T-072).

In scope: pure, bounded parsers of files an operator has already exported, normalization to
``appsec-review/crash-report/1``, binding to the reviewed revision, deterministic fault
classification, correlation with the published finding set, and the crash metrics.

Out of scope, and absent from this package: Crashpad or Breakpad integration, fetching crash data
from any service, reading or walking raw minidump files, symbolication tools or containers, and any
network access.

Crash bytes, module names, symbols, annotations and messages are untrusted data. They are never
evaluated, never become instructions and never become metric keys. Only the normalized record is
kept: user, device, host and session identifiers, addresses of people or machines, environments,
command lines, breadcrumbs, tags and free-text messages are dropped at parse time.
"""
from __future__ import annotations

from .adapters import ADAPTERS, ingest, parse, publish_evidence, register
from .binding import bind, bind_all
from .correlate import FAULT_FAMILIES, corroborate, fix_support, lead_candidates, metrics, missed_buckets
from .records import address_class, check_evidence, classify_fault, normalize_report, relativize, review_rank

__all__ = ["ADAPTERS", "FAULT_FAMILIES", "address_class", "bind", "bind_all", "check_evidence", "classify_fault",
           "corroborate", "fix_support", "ingest", "lead_candidates", "metrics", "missed_buckets",
           "normalize_report", "parse", "publish_evidence", "register", "relativize", "review_rank"]
