from benchmarks.historical_compatibility.stage1_selfdestruct_shadow import run_shadow


def test_stage1_modern_selfdestruct_shadow_is_in_parity():
    source = """
    pragma solidity 0.8.25;
    contract Victim {
        function destroy() public { selfdestruct(payable(msg.sender)); }
    }
    """
    result = run_shadow("modern.sol", source, "0.8.25")
    assert result["mode"] == "shadow-only"
    assert result["decision_effect"] == "none"
    assert result["baseline"]["finding_count"] == 1
    assert result["canonical"]["finding_count"] == 1
    assert result["comparison"]["finding_count_equal"] is True


def test_stage1_historical_suicide_divergence_is_visible():
    source = """
    pragma solidity ^0.4.10;
    contract Victim {
        function destroy() public { suicide(msg.sender); }
    }
    """
    result = run_shadow("historical.sol", source, "0.4.10")
    assert result["mode"] == "shadow-only"
    assert result["decision_effect"] == "none"
    assert result["canonical"]["finding_count"] == 1
    assert result["comparison"]["divergence"] is True
    assert result["baseline"]["finding_count"] == 0


def test_stage1_fixed_control_stays_clean():
    source = """
    pragma solidity 0.8.25;
    contract Safe {
        function noop() public {}
    }
    """
    result = run_shadow("fixed.sol", source, "0.8.25")
    assert result["baseline"]["finding_count"] == 0
    assert result["canonical"]["finding_count"] == 0
    assert result["comparison"]["finding_count_equal"] is True
