"""
CVSS 4.0 Scorer for smart contract vulnerabilities.

Two scoring paths, clearly labelled:
  1. OFFICIAL — when the `cvss` package (FIRST's reference implementation)
     is installed, vectors are scored with the real CVSS 4.0 specification.
  2. ESTIMATE — otherwise, an internal heuristic produces an approximation.
     Such results are marked method="internal_estimate" and must never be
     presented as official CVSS 4.0 publications.
"""
import math
from typing import Dict, Optional, Tuple

try:  # Official FIRST implementation — https://pypi.org/project/cvss/
    from cvss import CVSS4 as _OfficialCVSS4
    HAS_OFFICIAL_CVSS = True
except ImportError:
    _OfficialCVSS4 = None
    HAS_OFFICIAL_CVSS = False

_ESTIMATE_NOTE = (
    "Internal heuristic estimate — not an official FIRST CVSS 4.0 "
    "publication. Install the 'cvss' package for official scoring."
)

# Explicit CVSS 4.0 base metrics (issue #29). A finding is only an
# attribute assessment when all eight are supplied; anything else is
# either a labelled fallback estimate or "not assessed" — never a
# precise-looking score silently completed from a severity label.
_BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA")
_SUBSEQUENT_METRICS = ("SC", "SI", "SA")
_METRIC_LEGAL_VALUES = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "AT": {"N", "P"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "P", "A"},
    "VC": {"N", "L", "H"},
    "VI": {"N", "L", "H"},
    "VA": {"N", "L", "H"},
    "SC": {"N", "L", "H"},
    "SI": {"N", "L", "H"},
    "SA": {"N", "L", "H"},
}

# Phrases that negate a category mention in nearby text, e.g.
# "not vulnerable to reentrancy", "no reentrancy found",
# "reentrancy is not present". A negated mention must never trigger
# the positive category mapping (issue #29).
_NEGATION_WORDS = (
    "not", "no", "never", "without", "absent", "none",
    "not vulnerable", "not exploitable", "not present", "not affected",
    "no evidence", "no impact", "not applicable",
)

import re as _re


def _is_negated(text: str, start: int, end: int) -> bool:
    """True if a category mention at text[start:end] is negated nearby."""
    before = text[max(0, start - 60):start].lower()
    after = text[end:end + 40].lower()
    # Negation before the mention: "not vulnerable to reentrancy",
    # "no reentrancy", "without oracle manipulation".
    for phrase in _NEGATION_WORDS:
        if phrase in before:
            return True
    # Negation after the mention: "reentrancy is not present",
    # "reentrancy: not exploitable", "oracle manipulation — no impact".
    for phrase in ("not present", "not exploitable", "not vulnerable",
                   "not applicable", "is absent", "no impact", "not found"):
        if phrase in after:
            return True
    return False


def category_hint_vector(text: str):
    """Return (vector_part, category) for a non-negated category mention.

    Matching is word-boundary based, not raw substring matching, so
    e.g. "permissions" does not accidentally match a shorter key, and
    any negated mention is skipped entirely.
    """
    lowered = (text or "").lower()
    for key, (vec_part, _default_sev) in _VULN_CATEGORY_MAP.items():
        pattern = r"\b" + _re.escape(key) + r"\b"
        for match in _re.finditer(pattern, lowered):
            if not _is_negated(lowered, match.start(), match.end()):
                return vec_part, key
    return None, None


def validate_vector(vector: str):
    """Validate a CVSS 4.0 vector string. Returns a list of error strings.

    An empty list means the vector is well-formed: CVSS:4.0/ prefix,
    all eight base metrics present with legal values, and any
    subsequent metrics present with legal values.
    """
    errors = []
    if not vector or not vector.startswith("CVSS:4.0/"):
        return ["vector must start with 'CVSS:4.0/'"]
    seen_metrics = set()
    for part in vector[len("CVSS:4.0/"):].split("/"):
        metric, sep, _value = part.partition(":")
        if sep and metric in seen_metrics:
            errors.append(f"duplicate metric {metric}")
        if sep:
            seen_metrics.add(metric)
    metrics = parse_vector(vector)
    for metric in _BASE_METRICS:
        if metric not in metrics:
            errors.append(f"missing base metric {metric}")
        elif metrics[metric] not in _METRIC_LEGAL_VALUES[metric]:
            errors.append(
                f"illegal value {metrics[metric]!r} for metric {metric}")
    for metric, value in metrics.items():
        if metric not in _METRIC_LEGAL_VALUES:
            errors.append(f"unknown metric {metric}")
        elif value not in _METRIC_LEGAL_VALUES[metric]:
            errors.append(f"illegal value {value!r} for metric {metric}")
    return errors


def build_vector(attributes) -> str:
    """Build a canonical CVSS 4.0 vector from explicit attributes.

    All eight base metrics are required. Subsequent metrics default
    to N when not supplied. Raises ValueError listing missing metrics
    or illegal values instead of silently completing a vector.
    """
    attrs = {str(k).upper(): str(v).upper() for k, v in (attributes or {}).items()}
    missing = [m for m in _BASE_METRICS if m not in attrs]
    if missing:
        raise ValueError(f"missing CVSS attributes: {', '.join(missing)}")
    for metric, value in attrs.items():
        if metric not in _METRIC_LEGAL_VALUES:
            raise ValueError(f"unknown CVSS metric {metric}")
        if value not in _METRIC_LEGAL_VALUES[metric]:
            raise ValueError(f"illegal CVSS value {value!r} for metric {metric}")
    parts = []
    for metric in _BASE_METRICS + _SUBSEQUENT_METRICS:
        parts.append(f"{metric}:{attrs.get(metric, 'N')}")
    return "CVSS:4.0/" + "/".join(parts)


def parse_cvss_attributes(text: str):
    """Parse an explicit CVSS attribute/vector line, or return None.

    Only structured lines are read — e.g. a finding line
    "- **CVSS Attributes**: AV:N, AC:L, AT:N, PR:N, UI:N, VC:H, VI:H, VA:H"
    or "- **CVSS Vector**: CVSS:4.0/AV:N/...". Free-text descriptions
    are never parsed as attributes, so prose cannot fabricate them.
    Returns {"vector": ...} or {"attributes": {...}}.
    """
    if not text:
        return None
    vector_match = _re.search(r"CVSS:4\.0/[A-Za-z0-9/:]+", text)
    if vector_match:
        return {"vector": vector_match.group(0)}
    pairs = dict(_re.findall(r"\b(AV|AC|AT|PR|UI|VC|VI|VA|SC|SI|SA)\s*:\s*([A-Za-z])\b", text))
    if pairs:
        return {"attributes": pairs}
    return None


def _score_vector_with_provenance(vector: str, provenance: str) -> dict:
    """Score a validated vector, labelling official vs estimate."""
    official = _official_score(vector)
    if official is not None:
        return {"cvss_score": official, "method": "official",
                "note": "", "provenance": provenance, "status": "assessed"}
    metrics = parse_vector(vector)
    return {"cvss_score": compute_base_score(metrics),
            "method": "internal_estimate", "note": _ESTIMATE_NOTE,
            "provenance": provenance, "status": "assessed"}


def score_from_attributes(attributes) -> dict:
    """Score explicit CVSS attributes, or return 'not assessed'.

    Missing base attributes produce not_assessed (score None) rather
    than a vector silently completed from defaults or a severity label.
    """
    attrs = {str(k).upper(): str(v).upper() for k, v in (attributes or {}).items()}
    missing = [m for m in _BASE_METRICS if m not in attrs]
    if missing:
        return {"cvss_score": None, "cvss_vector": None,
                "cvss_severity": "Not Assessed", "method": "not_assessed",
                "provenance": "explicit_attributes",
                "status": "not_assessed",
                "note": ("Not assessed: missing CVSS attributes: "
                         + ", ".join(missing)),
                "missing": missing}
    try:
        vector = build_vector(attrs)
    except ValueError as exc:
        return {"cvss_score": None, "cvss_vector": None,
                "cvss_severity": "Not Assessed", "method": "not_assessed",
                "provenance": "explicit_attributes",
                "status": "not_assessed", "note": f"Not assessed: {exc}"}
    scored = _score_vector_with_provenance(vector, "explicit_attributes")
    scored.update({"cvss_vector": vector,
                   "cvss_severity": severity_from_score(scored["cvss_score"])})
    return scored


def score_from_vector(vector: str) -> dict:
    """Score an explicit vector, or return 'not assessed' if invalid."""
    errors = validate_vector(vector or "")
    if errors:
        return {"cvss_score": None, "cvss_vector": None,
                "cvss_severity": "Not Assessed", "method": "not_assessed",
                "provenance": "explicit_vector",
                "status": "not_assessed",
                "note": "Not assessed: invalid vector: " + "; ".join(errors),
                "errors": errors}
    scored = _score_vector_with_provenance(vector, "explicit_vector")
    scored.update({"cvss_vector": vector,
                   "cvss_severity": severity_from_score(scored["cvss_score"])})
    return scored


# CVSS 4.0 severity bands
SEVERITY_BANDS = {
    "None": (0.0, 0.0),
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10.0),
}

# Default CVSS 4.0 vectors by severity
_DEFAULT_VECTORS = {
    "Critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "High": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
    "Medium": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
    "Low": "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "Info": "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
}

# CVSS 4.0 metric numerical values (per CVSS 4.0 spec)
_METRIC_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.85, "H": 0.44},
    "AT": {"N": 0.85, "P": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "P": 0.62, "A": 0.44},
    "VC": {"H": 0.50, "L": 0.25, "N": 0.00},
    "VI": {"H": 0.50, "L": 0.25, "N": 0.00},
    "VA": {"H": 0.50, "L": 0.25, "N": 0.00},
    "SC": {"H": 0.20, "L": 0.10, "N": 0.00},
    "SI": {"H": 0.20, "L": 0.10, "N": 0.00},
    "SA": {"H": 0.20, "L": 0.10, "N": 0.00},
}

_VULN_CATEGORY_MAP = {
    "reentrancy": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "Critical"),
    "oracle manipulation": ("AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L", "High"),
    "flash loan": ("AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L", "High"),
    "access control": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H", "High"),
    "integer overflow": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N", "Medium"),
    "division by zero": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N", "Medium"),
    "signature replay": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L", "Medium"),
    "uninitialized proxy": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "Critical"),
    "denial of service": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H", "Medium"),
    "front running": ("AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N", "Low"),
    "gas griefing": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L", "Low"),
    "logic error": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H", "High"),
    "price manipulation": ("AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L", "High"),
    "sandwich attack": ("AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N", "Low"),
    "permission": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H", "High"),
}


def parse_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS 4.0 vector string into a dict of metric:value pairs."""
    parts = vector.replace("CVSS:4.0/", "").split("/")
    result = {}
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            result[k] = v
    return result


def _sub_score(metrics: Dict[str, str], keys) -> float:
    """Compute sub-score = 1 - prod(1 - val) for the given metric keys."""
    prod = 1.0
    for key in keys:
        val = metrics.get(key, "N")
        metric_vals = _METRIC_VALUES.get(key, {})
        prod *= (1.0 - metric_vals.get(val, 0.0))
    return 1.0 - prod


def _official_score(vector: str) -> Optional[float]:
    """Score a vector with the official FIRST implementation, if available."""
    if not HAS_OFFICIAL_CVSS:
        return None
    try:
        return round(float(_OfficialCVSS4(vector).base_score), 1)
    except Exception:
        return None


def compute_base_score(metrics: Dict[str, str]) -> float:
    """Internal heuristic estimate (NOT the official CVSS 4.0 formula).

    CVSS 4.0 defines no multiplicative equation; this approximation exists
    only as a fallback when the official 'cvss' package is unavailable and
    its results are always labelled as estimates.
    """
    eq1 = _sub_score(metrics, ["AV", "AC", "AT", "PR", "UI"])
    eq2 = _sub_score(metrics, ["VC", "VI", "VA"])
    eq3 = _sub_score(metrics, ["SC", "SI", "SA"])

    if eq2 <= 0.0 and eq3 <= 0.0:
        return 0.0

    score = 10.0 * eq1 * (1.0 - 0.5 * (1.0 - eq2) * (1.0 - eq3))
    return round(min(10.0, max(0.0, score)), 1)


def severity_from_score(score: float) -> str:
    """Map a CVSS 4.0 score (0-10) back to a severity band."""
    for sev, (lo, hi) in SEVERITY_BANDS.items():
        if lo <= score <= hi:
            return sev
    return "None"


def vector_from_severity(severity: str, category_hint: str = "") -> str:
    """Legacy hint vector (kept for backward compatibility only).

    Category matching is now word-boundary based and negated mentions
    are skipped, so "not reentrancy" no longer triggers the reentrancy
    vector. New assessments must use score_from_attributes() or
    score_from_vector() instead: a vector built from a severity label
    alone is a fallback estimate, never an attribute assessment, and
    score_report() labels it as such.
    """
    vec_part, _category = category_hint_vector(category_hint)
    if vec_part is not None:
        return f"CVSS:4.0/{vec_part}/SC:N/SI:N/SA:N"

    clean_sev = severity.replace("*", "").replace("`", "").strip()
    for key in _DEFAULT_VECTORS:
        if key.lower() == clean_sev.lower():
            return _DEFAULT_VECTORS[key]
    return _DEFAULT_VECTORS["Medium"]


def score_report(report: str) -> Dict:
    """Extract findings from a report and compute CVSS 4.0 scores for each.

    Precedence per finding:
      1. An explicit CVSS Vector / Attributes line -> attribute
         assessment (or "not assessed" if invalid/incomplete).
      2. Otherwise a legacy fallback estimate from a non-negated
         category hint or, failing that, the severity label alone.
         Fallbacks are labelled provenance="category_hint_estimate" or
         "severity_hint_estimate" and are never presented as official
         or as attribute assessments.
    """
    import re
    findings = []
    lines = report.split("\n")
    current = {}
    for line in lines:
        s = line.strip()
        if s.startswith("- **Name**"):
            if current and current.get("name"):
                findings.append(current)
            current = {"name": s.split(":", 1)[1].strip() if ":" in s else ""}
        elif s.startswith("- **Severity**") and current:
            raw = s.split(":", 1)[1].strip() if ":" in s else "Medium"
            current["severity"] = raw.replace("*", "").replace("`", "").strip()
        elif s.startswith("- **Description**") and current:
            current["description"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif current and (s.startswith("- **CVSS Attributes**")
                          or s.startswith("- **CVSS Vector**")
                          or s.startswith("- **Vector**")):
            parsed = parse_cvss_attributes(s.split(":", 1)[1] if ":" in s else "")
            if parsed:
                current["cvss_explicit"] = parsed

    if current and current.get("name"):
        findings.append(current)

    scored = []
    for f in findings:
        name = f.get("name", "?")
        sev = f.get("severity", "Medium")
        desc = f.get("description", "")
        explicit = f.get("cvss_explicit")
        if explicit and "vector" in explicit:
            result = score_from_vector(explicit["vector"])
            result.update({"name": name, "severity": sev,
                           "requested_severity": sev})
            scored.append(result)
            continue
        if explicit and "attributes" in explicit:
            result = score_from_attributes(explicit["attributes"])
            result.update({"name": name, "severity": sev,
                           "requested_severity": sev})
            scored.append(result)
            continue
        # Legacy fallback: labelled estimate, never an assessment.
        vec_part, category = category_hint_vector(desc)
        if vec_part is not None:
            vector = f"CVSS:4.0/{vec_part}/SC:N/SI:N/SA:N"
            provenance = "category_hint_estimate"
            fallback_note = (
                "Category-hint estimate — not assessed from explicit "
                f"CVSS attributes (hint: {category}); " + _ESTIMATE_NOTE)
        else:
            vector = vector_from_severity(sev, "")
            provenance = "severity_hint_estimate"
            fallback_note = (
                "Severity-hint estimate — vector derived from the "
                "severity label alone, not from explicit CVSS "
                "attributes; " + _ESTIMATE_NOTE)
        scored_part = _score_vector_with_provenance(vector, provenance)
        scored.append({
            "name": name,
            "severity": sev,
            "cvss_vector": vector,
            "cvss_score": scored_part["cvss_score"],
            "cvss_severity": severity_from_score(scored_part["cvss_score"]),
            "requested_severity": sev,
            "method": scored_part["method"],
            "note": fallback_note if scored_part["method"] == "internal_estimate" else (
                "Category/severity-hint estimate scored with the official "
                "formula — still not an attribute assessment; "
                f"provenance: {provenance}."),
            "provenance": provenance,
            "status": "fallback_estimate",
        })

    numeric_scores = [s["cvss_score"] for s in scored
                      if isinstance(s.get("cvss_score"), (int, float))]
    if numeric_scores:
        overall_score = max(numeric_scores)
        overall_severity = severity_from_score(overall_score)
        # Basis of the max: an assessed finding at the max makes the
        # overall an assessment; otherwise the max is only an estimate.
        # Renderers must use this, never present a fallback max as a
        # computed score.
        at_max = [s for s in scored if s.get("cvss_score") == overall_score]
        if any(s.get("status") == "assessed" for s in at_max):
            overall_basis = "assessed"
        else:
            overall_basis = "estimate"
    else:
        # Nothing was scored: no numeric overall. A 0.0 here would read
        # as "safe" (severity None), so the overall is explicitly None
        # and renderers must show "Not assessed — no score" instead.
        overall_score = None
        overall_severity = "Not Assessed"
        overall_basis = "not_assessed"
    if not scored or all(s.get("status") == "not_assessed" for s in scored):
        overall_status = "not_assessed"
    elif any(s.get("status") == "not_assessed" for s in scored):
        overall_status = "partially_assessed"
    else:
        overall_status = "assessed_or_estimated"

    return {
        "findings": scored,
        "overall_score": overall_score,
        "overall_severity": overall_severity,
        "overall_status": overall_status,
        "overall_basis": overall_basis,
        "total_findings": len(scored),
    }


def format_finding_score(finding: dict) -> str:
    """One-line client-facing rendering of a single scored finding.

    A fallback estimate is always labelled "estimate" in plain words
    (never a bare "X/10" with only a method/provenance code beside it,
    which reads as official when method is "official"), and a
    not-assessed finding carries no numeric score at all.
    """
    status = finding.get("status", "not_assessed")
    score = finding.get("cvss_score")
    severity = finding.get("cvss_severity", "")
    vector = finding.get("cvss_vector")
    provenance = finding.get("provenance", "")
    method = finding.get("method", "")
    if status == "not_assessed" or score is None:
        text = "Not assessed — no score"
        note = finding.get("note", "")
        if note:
            text += f" ({note})"
        return text
    if status == "fallback_estimate":
        text = (f"{score}/10 ({severity}) — estimate "
                "(not an attribute assessment")
        if method == "official":
            text += "; scored with the official formula, still an estimate"
        if provenance:
            text += f"; provenance: {provenance}"
        text += ")"
        if vector:
            text += f" — `{vector}`"
        return text
    # Assessed from explicit attributes/vector.
    text = f"{score}/10 ({severity}) — assessed"
    if method == "internal_estimate":
        text += (" (internal estimate — not an official FIRST "
                 "CVSS 4.0 publication")
    elif method:
        text += f" (method: {method}"
    if provenance:
        text += f", provenance: {provenance}"
    text += ")"
    if vector:
        text += f" — `{vector}`"
    return text


def format_overall_score(cvss_result: dict) -> str:
    """One-line client-facing rendering of a score_report overall.

    Not-assessed (or empty) results render as "Not assessed — no
    score" with no number; an estimate-only max is labelled estimate.
    """
    if cvss_result.get("overall_score") is None:
        return "Not assessed — no score"
    score = cvss_result["overall_score"]
    severity = cvss_result.get("overall_severity", "")
    if cvss_result.get("overall_basis") == "estimate":
        return (f"{score}/10 ({severity}) — estimate "
                "(overall max comes from fallback estimates only, "
                "not from explicit CVSS attributes)")
    return f"{score}/10 ({severity})"


def _first_letter(value, metric: str) -> str:
    """Map a metric argument to its CVSS letter, validating it.

    Accepts a single letter ("N") or a word ("Network" -> "N").
    Raises ValueError for anything that does not map to a legal value
    instead of silently scoring a mis-parsed metric.
    """
    if not value:
        raise ValueError(f"missing CVSS metric {metric}")
    letter = str(value).strip()[0].upper()
    if letter not in _METRIC_LEGAL_VALUES[metric]:
        raise ValueError(f"illegal CVSS value {value!r} for metric {metric}")
    return letter


def compute_cvss_detailed(attack_vector: str = "N", complexity: str = "L",
                          privileges: str = "N", user_interaction: str = "N",
                          confidentiality: str = "H", integrity: str = "H",
                          availability: str = "H") -> Dict:
    """Compute CVSS 4.0 from explicit metric values, with provenance.

    AT, SC, SI and SA are not parameters of this helper and are fixed
    to N; that limitation is stated in the returned note, not hidden.
    Returns a dict including method ("official" or "internal_estimate")
    so callers can never mistake an estimate for an official score.
    """
    metrics = {
        "AV": _first_letter(attack_vector, "AV"),
        "AC": _first_letter(complexity, "AC"),
        "AT": "N",
        "PR": _first_letter(privileges, "PR"),
        "UI": _first_letter(user_interaction, "UI"),
        "VC": _first_letter(confidentiality, "VC"),
        "VI": _first_letter(integrity, "VI"),
        "VA": _first_letter(availability, "VA"),
        "SC": "N",
        "SI": "N",
        "SA": "N",
    }
    vector = build_vector(metrics)
    scored = _score_vector_with_provenance(vector, "explicit_attributes")
    note = scored["note"]
    if note:
        note += " AT/SC/SI/SA fixed to N by this helper."
    return {
        "cvss_score": scored["cvss_score"],
        "cvss_severity": severity_from_score(scored["cvss_score"]),
        "cvss_vector": vector,
        "method": scored["method"],
        "provenance": "explicit_attributes",
        "status": "assessed",
        "note": note,
        "attributes": metrics,
    }


def compute_cvss(attack_vector: str = "N", complexity: str = "L",
                 privileges: str = "N", user_interaction: str = "N",
                 confidentiality: str = "H", integrity: str = "H",
                 availability: str = "H") -> Tuple[float, str, str]:
    """Compute CVSS 4.0 from individual metric values. Returns (score, severity, vector).

    Kept as a tuple for backward compatibility with the web UI; use
    compute_cvss_detailed() when provenance (official vs estimate)
    matters, which it does for any client-facing output.
    """
    detailed = compute_cvss_detailed(
        attack_vector, complexity, privileges, user_interaction,
        confidentiality, integrity, availability)
    return detailed["cvss_score"], detailed["cvss_severity"], detailed["cvss_vector"]


def cvss_explanation(score, severity: str, vector: str) -> str:
    """Generate a human-readable explanation of the CVSS score.

    A None score (not assessed) renders as "Not assessed — no score"
    with no numeric score and no metric breakdown built from an
    unrelated vector.
    """
    if score is None:
        return ("**CVSS 4.0 Score**: Not assessed — no score\n\n"
                "No CVSS vector was assessed for this report.")
    metrics = parse_vector(vector or "")
    parts = [
        f"**CVSS 4.0 Score**: {score}/10 ({severity})",
        f"**Vector**: `{vector}`",
        "",
        "### Metric Breakdown",
        f"- **Attack Vector (AV)**: {_metric_label(metrics.get('AV','N'), 'AV')}",
        f"- **Attack Complexity (AC)**: {_metric_label(metrics.get('AC','L'), 'AC')}",
        f"- **Privileges Required (PR)**: {_metric_label(metrics.get('PR','N'), 'PR')}",
        f"- **User Interaction (UI)**: {_metric_label(metrics.get('UI','N'), 'UI')}",
        f"- **Confidentiality (VC)**: {_metric_label(metrics.get('VC','H'), 'VC')}",
        f"- **Integrity (VI)**: {_metric_label(metrics.get('VI','H'), 'VI')}",
        f"- **Availability (VA)**: {_metric_label(metrics.get('VA','H'), 'VA')}",
    ]
    return "\n".join(parts)


def _metric_label(val: str, metric: str) -> str:
    labels = {
        "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
        "AC": {"L": "Low", "H": "High"},
        "AT": {"N": "None", "P": "Present"},
        "PR": {"N": "None", "L": "Low", "H": "High"},
        "UI": {"N": "None", "P": "Passive", "A": "Active"},
        "VC": {"H": "High", "L": "Low", "N": "None"},
        "VI": {"H": "High", "L": "Low", "N": "None"},
        "VA": {"H": "High", "L": "Low", "N": "None"},
        "SC": {"H": "High", "L": "Low", "N": "None"},
        "SI": {"H": "High", "L": "Low", "N": "None"},
        "SA": {"H": "High", "L": "Low", "N": "None"},
    }
    return labels.get(metric, {}).get(val, val)
