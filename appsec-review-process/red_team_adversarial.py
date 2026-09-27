#!/usr/bin/env python3
import argparse
from pathlib import Path
from claim_lifecycle_core import run_stage

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalize nominal red-team claim hypotheses.")
    parser.add_argument("--run-id", required=True); parser.add_argument("--accepted", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(); run_stage("07-red-team-adversarial", args.accepted, args.decisions, args.output, args.run_id)
