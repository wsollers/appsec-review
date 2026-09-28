#!/usr/bin/env python3
"""Pinned CVSS v4.0 scoring (FIRST CVSS v4.0 specification, November 2023).

The model never computes a score.  At ``12-scoring-prioritization`` it proposes the eleven base
metric values with one justification per metric; this module validates the values, builds the
canonical vector string and computes the score and qualitative severity the way the FIRST reference
calculator (``cvss_score.js`` + ``cvss_lookup.js``, macrovector interpolation) does, including its
``Math.round(x * 10) / 10`` rounding.

The 270-entry macrovector table and the per-EQ maximal vectors are transcribed from the FIRST
reference implementation.  ``LOOKUP_SHA256`` pins the table so an accidental edit fails closed;
``tests/test_cvss4.py`` holds the calculator test vectors (ADR-0020).
"""
from __future__ import annotations

import hashlib
import itertools
import json
import math
from typing import Any

VERSION = "CVSS:4.0"
IMPLEMENTATION = "appsec-review cvss4.py (FIRST CVSS v4.0 reference algorithm)"

BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
BASE_VALUES = {
    "AV": ("N", "A", "L", "P"), "AC": ("L", "H"), "AT": ("N", "P"), "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"), "VC": ("H", "L", "N"), "VI": ("H", "L", "N"), "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"), "SI": ("H", "L", "N"), "SA": ("H", "L", "N"),
}
OPTIONAL_VALUES = {
    "E": ("X", "A", "P", "U"),
    "CR": ("X", "H", "M", "L"), "IR": ("X", "H", "M", "L"), "AR": ("X", "H", "M", "L"),
    "MAV": ("X", "N", "A", "L", "P"), "MAC": ("X", "L", "H"), "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"), "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "H", "L", "N"), "MVI": ("X", "H", "L", "N"), "MVA": ("X", "H", "L", "N"),
    "MSC": ("X", "H", "L", "N"), "MSI": ("X", "S", "H", "L", "N"), "MSA": ("X", "S", "H", "L", "N"),
    "S": ("X", "N", "P"), "AU": ("X", "N", "Y"), "R": ("X", "A", "U", "I"),
    "V": ("X", "D", "C"), "RE": ("X", "L", "M", "H"), "U": ("X", "Clear", "Green", "Amber", "Red"),
}
ORDER = BASE_METRICS + tuple(OPTIONAL_VALUES)

# Severity distances inside a macrovector (units of 0.1), from the reference calculator.
LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}, "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2}, "AC": {"L": 0.0, "H": 0.1}, "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2}, "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2}, "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}, "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2}, "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2}, "E": {"U": 0.2, "P": 0.1, "A": 0.0},
}

MAX_COMPOSED = {
    "eq1": {0: ["AV:N/PR:N/UI:N/"], 1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
            2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]},
    "eq2": {0: ["AC:L/AT:N/"], 1: ["AC:H/AT:N/", "AC:L/AT:P/"]},
    "eq3": {0: {0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
                1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]},
            1: {0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
                1: ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                    "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                    "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]},
            2: {1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]}},
    "eq4": {0: ["SC:H/SI:S/SA:S/"], 1: ["SC:H/SI:H/SA:H/"], 2: ["SC:L/SI:L/SA:L/"]},
    "eq5": {0: ["E:A/"], 1: ["E:P/"], 2: ["E:U/"]},
}
MAX_SEVERITY = {
    "eq1": {0: 1, 1: 4, 2: 5}, "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4}, "eq5": {0: 1, 1: 1, 2: 1},
}

_TABLE = """
000000 10 000001 9.9 000010 9.8 000011 9.5 000020 9.5 000021 9.2 000100 10 000101 9.6
000110 9.3 000111 8.7 000120 9.1 000121 8.1 000200 9.3 000201 9 000210 8.9 000211 8
000220 8.1 000221 6.8 001000 9.8 001001 9.5 001010 9.5 001011 9.2 001020 9 001021 8.4
001100 9.3 001101 9.2 001110 8.9 001111 8.1 001120 8.1 001121 6.5 001200 8.8 001201 8
001210 7.8 001211 7 001220 6.9 001221 4.8 002001 9.2 002011 8.2 002021 7.2 002101 7.9
002111 6.9 002121 5 002201 6.9 002211 5.5 002221 2.7 010000 9.9 010001 9.7 010010 9.5
010011 9.2 010020 9.2 010021 8.5 010100 9.5 010101 9.1 010110 9 010111 8.3 010120 8.4
010121 7.1 010200 9.2 010201 8.1 010210 8.2 010211 7.1 010220 7.2 010221 5.3 011000 9.5
011001 9.3 011010 9.2 011011 8.5 011020 8.5 011021 7.3 011100 9.2 011101 8.2 011110 8
011111 7.2 011120 7 011121 5.9 011200 8.4 011201 7 011210 7.1 011211 5.2 011220 5
011221 3 012001 8.6 012011 7.5 012021 5.2 012101 7.1 012111 5.2 012121 2.9 012201 6.3
012211 2.9 012221 1.7 100000 9.8 100001 9.5 100010 9.4 100011 8.7 100020 9.1 100021 8.1
100100 9.4 100101 8.9 100110 8.6 100111 7.4 100120 7.7 100121 6.4 100200 8.7 100201 7.5
100210 7.4 100211 6.3 100220 6.3 100221 4.9 101000 9.4 101001 8.9 101010 8.8 101011 7.7
101020 7.6 101021 6.7 101100 8.6 101101 7.6 101110 7.4 101111 5.8 101120 5.9 101121 5
101200 7.2 101201 5.7 101210 5.7 101211 5.2 101220 5.2 101221 2.5 102001 8.3 102011 7
102021 5.4 102101 6.5 102111 5.8 102121 2.6 102201 5.3 102211 2.1 102221 1.3 110000 9.5
110001 9 110010 8.8 110011 7.6 110020 7.6 110021 7 110100 9 110101 7.7 110110 7.5
110111 6.2 110120 6.1 110121 5.3 110200 7.7 110201 6.6 110210 6.8 110211 5.9 110220 5.2
110221 3 111000 8.9 111001 7.8 111010 7.6 111011 6.7 111020 6.2 111021 5.8 111100 7.4
111101 5.9 111110 5.7 111111 5.7 111120 4.7 111121 2.3 111200 6.1 111201 5.2 111210 5.7
111211 2.9 111220 2.4 111221 1.6 112001 7.1 112011 5.9 112021 3 112101 5.8 112111 2.6
112121 1.5 112201 2.3 112211 1.3 112221 0.6 200000 9.3 200001 8.7 200010 8.6 200011 7.2
200020 7.5 200021 5.8 200100 8.6 200101 7.4 200110 7.4 200111 6.1 200120 5.6 200121 3.4
200200 7 200201 5.4 200210 5.2 200211 4 200220 4 200221 2.2 201000 8.5 201001 7.5
201010 7.4 201011 5.5 201020 6.2 201021 5.1 201100 7.2 201101 5.7 201110 5.5 201111 4.1
201120 4.6 201121 1.9 201200 5.3 201201 3.6 201210 3.4 201211 1.9 201220 1.9 201221 0.8
202001 6.4 202011 5.1 202021 2 202101 4.7 202111 2.1 202121 1.1 202201 2.4 202211 0.9
202221 0.4 210000 8.8 210001 7.5 210010 7.3 210011 5.3 210020 6 210021 5 210100 7.3
210101 5.5 210110 5.9 210111 4 210120 4.1 210121 2 210200 5.4 210201 4.3 210210 4.5
210211 2.2 210220 2 210221 1.1 211000 7.5 211001 5.5 211010 5.8 211011 4.5 211020 4
211021 2.1 211100 6.1 211101 5.1 211110 4.8 211111 1.8 211120 2 211121 0.9 211200 4.6
211201 1.8 211210 1.7 211211 0.7 211220 0.8 211221 0.2 212001 5.3 212011 2.4 212021 1.4
212101 2.4 212111 1.2 212121 0.5 212201 1 212211 0.3 212221 0.1
"""
_TOKENS = _TABLE.split()
LOOKUP: dict[str, float] = {_TOKENS[i]: float(_TOKENS[i + 1]) for i in range(0, len(_TOKENS), 2)}
LOOKUP_SHA256 = "sha256:ca8d8866186b0dda0f9f84bd9ce8bfba15f493fdaf9407cc7af0931c3d0ad01a"


def lookup_sha256() -> str:
    return "sha256:" + hashlib.sha256(json.dumps(LOOKUP, sort_keys=True).encode()).hexdigest()


class CVSSError(ValueError):
    """An invalid metric value or vector; the message names the metric."""


def parse(vector: str) -> dict[str, str]:
    if not isinstance(vector, str) or not vector.startswith(VERSION + "/"):
        raise CVSSError("vector must start with CVSS:4.0/")
    metrics: dict[str, str] = {}
    last = -1
    for part in vector[len(VERSION) + 1:].split("/"):
        key, sep, value = part.partition(":")
        if not sep or key not in ORDER:
            raise CVSSError(f"unknown metric {part!r}")
        if key in metrics:
            raise CVSSError(f"duplicate metric {key}")
        if ORDER.index(key) < last:
            raise CVSSError(f"metric {key} is out of the specification order")
        last = ORDER.index(key)
        allowed = BASE_VALUES.get(key) or OPTIONAL_VALUES[key]
        if value not in allowed:
            raise CVSSError(f"metric {key} value {value!r} is not one of {list(allowed)}")
        metrics[key] = value
    missing = [key for key in BASE_METRICS if key not in metrics]
    if missing:
        raise CVSSError(f"mandatory base metric(s) missing: {missing}")
    return metrics


def vector_from_base(metrics: dict[str, str]) -> str:
    """Canonical base vector from exactly the eleven base metrics."""
    if not isinstance(metrics, dict) or set(metrics) != set(BASE_METRICS):
        raise CVSSError(f"base metrics must be exactly {list(BASE_METRICS)}")
    for key in BASE_METRICS:
        if metrics[key] not in BASE_VALUES[key]:
            raise CVSSError(f"metric {key} value {metrics[key]!r} is not one of {list(BASE_VALUES[key])}")
    return VERSION + "/" + "/".join(f"{key}:{metrics[key]}" for key in BASE_METRICS)


def _effective(metrics: dict[str, str]) -> dict[str, str]:
    """Metric values with the X defaults applied (E:X->A, CR/IR/AR:X->H, M*:X->base)."""
    result = {}
    for key in BASE_METRICS:
        modified = metrics.get("M" + key, "X")
        result[key] = metrics[key] if modified == "X" else modified
    result["E"] = "A" if metrics.get("E", "X") == "X" else metrics["E"]
    for key in ("CR", "IR", "AR"):
        result[key] = "H" if metrics.get(key, "X") == "X" else metrics[key]
    return result


def macrovector(metrics: dict[str, str]) -> str:
    m = _effective(metrics)
    if m["AV"] == "N" and m["PR"] == "N" and m["UI"] == "N":
        eq1 = 0
    elif (m["AV"] == "N" or m["PR"] == "N" or m["UI"] == "N") and m["AV"] != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if m["AC"] == "L" and m["AT"] == "N" else 1
    if m["VC"] == "H" and m["VI"] == "H":
        eq3 = 0
    elif "H" in (m["VC"], m["VI"], m["VA"]):
        eq3 = 1
    else:
        eq3 = 2
    if m["SI"] == "S" or m["SA"] == "S":
        eq4 = 0
    elif "H" in (m["SC"], m["SI"], m["SA"]):
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[m["E"]]
    eq6 = 0 if ((m["CR"] == "H" and m["VC"] == "H") or (m["IR"] == "H" and m["VI"] == "H") or
                (m["AR"] == "H" and m["VA"] == "H")) else 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _extract(max_vector: str, key: str) -> str:
    for part in max_vector.split("/"):
        name, _, value = part.partition(":")
        if name == key:
            return value
    raise CVSSError(f"internal: {key} absent from maximal vector")


def _js_round(value: float) -> float:
    return math.floor(value * 10 + 0.5) / 10


def score(vector: str | dict[str, str]) -> float:
    if lookup_sha256() != LOOKUP_SHA256:
        raise CVSSError("pinned CVSS v4.0 macrovector table changed")
    metrics = parse(vector) if isinstance(vector, str) else parse(vector_from_base(vector))
    m = _effective(metrics)
    if all(m[key] == "N" for key in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    macro = macrovector(metrics)
    value = LOOKUP[macro]
    eq = [int(ch) for ch in macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = eq

    def key(delta: dict[int, int]) -> str:
        return "".join(str(eq[i] + delta.get(i, 0)) for i in range(6))

    nan = float("nan")
    lower = {name: LOOKUP.get(key({index: 1}), nan)
             for name, index in (("eq1", 0), ("eq2", 1), ("eq4", 3), ("eq5", 4))}
    if eq3 == 1 and eq6 == 1:
        lower["eq3eq6"] = LOOKUP.get(key({2: 1}), nan)
    elif eq3 == 0 and eq6 == 1:
        lower["eq3eq6"] = LOOKUP.get(key({2: 1}), nan)
    elif eq3 == 1 and eq6 == 0:
        lower["eq3eq6"] = LOOKUP.get(key({5: 1}), nan)
    elif eq3 == 0 and eq6 == 0:
        left, right = LOOKUP.get(key({5: 1}), nan), LOOKUP.get(key({2: 1}), nan)
        lower["eq3eq6"] = left if left > right else right
    else:
        lower["eq3eq6"] = LOOKUP.get(key({2: 1, 5: 1}), nan)

    maxima = [MAX_COMPOSED["eq1"][eq1], MAX_COMPOSED["eq2"][eq2], MAX_COMPOSED["eq3"][eq3][eq6],
              MAX_COMPOSED["eq4"][eq4], MAX_COMPOSED["eq5"][eq5]]
    names = ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR")
    distance: dict[str, float] = {}
    for combination in itertools.product(*maxima):
        max_vector = "".join(combination)
        distance = {name: LEVELS[name][m[name]] - LEVELS[name][_extract(max_vector, name)] for name in names}
        if all(item >= 0 for item in distance.values()):
            break
    current = {
        "eq1": distance["AV"] + distance["PR"] + distance["UI"],
        "eq2": distance["AC"] + distance["AT"],
        "eq3eq6": sum(distance[name] for name in ("VC", "VI", "VA", "CR", "IR", "AR")),
        "eq4": distance["SC"] + distance["SI"] + distance["SA"],
    }
    step = 0.1
    depth = {"eq1": MAX_SEVERITY["eq1"][eq1] * step, "eq2": MAX_SEVERITY["eq2"][eq2] * step,
             "eq3eq6": MAX_SEVERITY["eq3eq6"][eq3][eq6] * step, "eq4": MAX_SEVERITY["eq4"][eq4] * step}
    existing, total = 0, 0.0
    for name in ("eq1", "eq2", "eq3eq6", "eq4", "eq5"):
        available = value - lower[name]
        if math.isnan(available):
            continue
        existing += 1
        if name != "eq5":  # the reference calculator uses a zero proportion for EQ5
            total += available * (current[name] / depth[name])
    mean = total / existing if existing else 0.0
    value = min(10.0, max(0.0, value - mean))
    return _js_round(value)


def severity(value: float) -> str:
    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    if value >= 0.1:
        return "LOW"
    return "NONE"


def assess(metrics: dict[str, str], rationale: dict[str, str]) -> dict[str, Any]:
    """Validate a model's base-metric proposal and compute the authoritative CVSS record."""
    vector = vector_from_base(metrics)
    if not isinstance(rationale, dict) or set(rationale) != set(BASE_METRICS) or any(
            not isinstance(text, str) or not text.strip() for text in rationale.values()):
        raise CVSSError(f"one non-empty justification is required for each of {list(BASE_METRICS)}")
    value = score(vector)
    return {"version": "4.0", "vector": vector, "score": value, "severity": severity(value),
            "macrovector": macrovector(parse(vector)),
            "metric_rationale": {key: rationale[key].strip()[:600] for key in BASE_METRICS},
            "calculator": {"implementation": IMPLEMENTATION, "lookup_sha256": LOOKUP_SHA256}}


if __name__ == "__main__":
    import sys
    for item in sys.argv[1:]:
        result = score(item)
        print(f"{item} {result} {severity(result)}")
