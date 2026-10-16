"""Job-neutral seeding: finding locations that bound every seeded producer's neighborhood."""

from .ledger import *  # noqa: F401,F403
from .ledger import (  # noqa: F401
    CLANG_STATIC_JOB, CODEQL_JOB, COMPILED_JOB, CPG_JOB, FILE_NOT_IN_DATABASE, LEDGER_STATUSES,
    MAX_FUNCTIONS_PER_SEED, MAX_SOURCES_PER_SEED, NO_SEEDS_GAP, OVER_LIMIT, RESOLVED,
    SEEDED_PRODUCER_JOBS, ScopeSeeds, Seed, SeedIntegrityError, SeedPlan, SeedScope, SeedSource,
    UNRESOLVED, database_path, extract_seeds, identity_fragment, observation_shards, scope_csv,
    seeded_section, seeds_csv, skipped_section, whole_program_section,
)
from .plan import project_scope, seed_plan, source_reader  # noqa: E402,F401
from .record import (  # noqa: E402,F401
    ProjectScope, compact_record, coverage_gap, resolved_keys, with_reasons,
)


def implementation_sources() -> tuple["Path", ...]:
    """Every source file of this package, for a producer job's implementation identity."""
    from pathlib import Path

    return tuple(sorted(Path(__file__).parent.glob("*.py")))
