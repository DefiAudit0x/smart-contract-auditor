"""Regression tests for issue #29: CVSS from attributes, not labels.

Solc-free by design: cvss_scorer has no compiler dependency.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

import cvss_scorer as cvss


HIGH_ATTRS = {
    "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
    "VC": "H", "VI": "H", "VA": "H",
}
EXPECTED_HIGH_VECTOR = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
)


def _report(name, severity, description, extra=""):
    return (
        f"- **Name**: {name}\n"
        f"- **Severity**: {severity}\n"
        f"- **Description**: {description}\n"
        f"{extra}"
    )


class TestExplicitAttributes:
    def test_explicit_attributes_produce_expected_vector_and_provenance(self):
        result = cvss.score_from_attributes(HIGH_ATTRS)
        assert result["cvss_vector"] == EXPECTED_HIGH_VECTOR
        assert result["status"] == "assessed"
        assert result["provenance"] == "explicit_attributes"
        assert result["method"] in ("official", "internal_estimate")
        assert isinstance(result["cvss_score"], float)
        assert 0.0 <= result["cvss_score"] <= 10.0

    def test_explicit_attributes_via_report(self):
        attrs = "AV:N, AC:L, AT:N, PR:N, UI:N, VC:H, VI:H, VA:H"
        report = _report(
            "Reentrancy", "Critical", "withdraw drains funds",
            f"- **CVSS Attributes**: {attrs}\n")
        entry = cvss.score_report(report)["findings"][0]
        assert entry["cvss_vector"] == EXPECTED_HIGH_VECTOR
        assert entry["provenance"] == "explicit_attributes"
        assert entry["status"] == "assessed"

    def test_explicit_vector_via_report(self):
        report = _report(
            "Reentrancy", "Critical", "withdraw drains funds",
            f"- **CVSS Vector**: {EXPECTED_HIGH_VECTOR}\n")
        entry = cvss.score_report(report)["findings"][0]
        assert entry["cvss_vector"] == EXPECTED_HIGH_VECTOR
        assert entry["provenance"] == "explicit_vector"
        assert entry["status"] == "assessed"

    def test_different_prerequisites_produce_different_vectors(self):
        local_priv = dict(HIGH_ATTRS, AV="L", PR="H", VC="L", VI="L", VA="L")
        high = cvss.score_from_attributes(HIGH_ATTRS)
        low = cvss.score_from_attributes(local_priv)
        assert high["cvss_vector"] != low["cvss_vector"]
        assert low["cvss_score"] <= high["cvss_score"]

    def test_compute_cvss_detailed_validates_and_labels(self):
        detailed = cvss.compute_cvss_detailed("N", "L", "N", "N", "H", "H", "H")
        assert detailed["cvss_vector"] == EXPECTED_HIGH_VECTOR
        assert detailed["provenance"] == "explicit_attributes"
        assert detailed["method"] in ("official", "internal_estimate")
        with pytest.raises(ValueError):
            cvss.compute_cvss_detailed("X", "L", "N", "N", "H", "H", "H")


class TestNegation:
    @pytest.mark.parametrize("text", [
        "not vulnerable to reentrancy",
        "no reentrancy found",
        "reentrancy is not present",
        "without oracle manipulation",
        "oracle manipulation is not exploitable",
        "no impact from front running",
    ])
    def test_negated_phrase_does_not_trigger_category(self, text):
        vec_part, category = cvss.category_hint_vector(text)
        assert vec_part is None
        assert category is None

    def test_positive_phrase_still_triggers_category(self):
        vec_part, category = cvss.category_hint_vector(
            "classic reentrancy in withdraw")
        assert category == "reentrancy"
        assert vec_part is not None

    def test_negated_description_falls_back_to_severity_hint(self):
        report = _report("Withdraw", "Medium", "not vulnerable to reentrancy")
        entry = cvss.score_report(report)["findings"][0]
        assert entry["provenance"] == "severity_hint_estimate"
        assert entry["status"] == "fallback_estimate"
        # The Medium severity-default vector, not the reentrancy vector.
        assert entry["cvss_vector"] == cvss._DEFAULT_VECTORS["Medium"]


class TestFallbackAndNotAssessed:
    def test_fallback_is_labelled_not_an_attribute_assessment(self):
        report = _report("Withdraw", "High", "reentrancy drains funds")
        entry = cvss.score_report(report)["findings"][0]
        assert entry["status"] == "fallback_estimate"
        assert entry["provenance"] == "category_hint_estimate"
        assert "not assessed from explicit" in entry["note"]

    def test_missing_attributes_produce_not_assessed(self):
        result = cvss.score_from_attributes({"AV": "N", "PR": "N"})
        assert result["status"] == "not_assessed"
        assert result["cvss_score"] is None
        assert result["cvss_vector"] is None
        assert "AC" in result["missing"]
        assert "VC" in result["missing"]

    def test_partial_attributes_line_in_report_is_not_assessed(self):
        report = _report(
            "Withdraw", "High", "reentrancy drains funds",
            "- **CVSS Attributes**: AV:N, PR:N\n")
        entry = cvss.score_report(report)["findings"][0]
        assert entry["status"] == "not_assessed"
        assert entry["cvss_score"] is None

    def test_invalid_vector_is_not_assessed(self):
        errors = cvss.validate_vector("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
        assert errors
        result = cvss.score_from_vector("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
        assert result["status"] == "not_assessed"
        assert result["cvss_score"] is None

    def test_valid_vector_passes_validation(self):
        assert cvss.validate_vector(EXPECTED_HIGH_VECTOR) == []

    def test_build_vector_rejects_illegal_value(self):
        with pytest.raises(ValueError):
            cvss.build_vector(dict(HIGH_ATTRS, AV="X"))
