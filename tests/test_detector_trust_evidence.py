"""Regression tests for detector trust: issues #20, #23, #24.

Principle, shared by all three: a finding is CONFIRMED only with code
evidence tied to the relevant condition. Heuristic suspicion, prose kill
signals, and mere presence of a related API are never confirmed findings.
"""
import bug_detector
import ai_tools
import zksync_detector


# ---------------------------------------------------------------- #20
def _reentrancy_summary(code):
    for entry in bug_detector.get_summary(code):
        if entry["class"] == "reentrancy":
            return entry
    return {"match_count": 0, "matches": [], "suppressed_count": 0, "suppressions": []}


GUARDED_WITHDRAW = """
contract V {
    mapping(address=>uint) public balances;
    function withdraw(uint amount) external nonReentrant {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "fail");
        balances[msg.sender] = 0;
    }
}
"""

UNGUARDED_WITHDRAW = GUARDED_WITHDRAW.replace(" nonReentrant", "")


def test_kill_signal_suppresses_guarded_reentrancy():
    entry = _reentrancy_summary(GUARDED_WITHDRAW)
    assert entry["match_count"] == 0
    assert entry["suppressed_count"] == 1
    sup = entry["suppressions"][0]
    assert sup["status"] == "suppressed_by_kill_signal"
    assert "nonReentrant" in sup["kill_reason"]
    assert sup["kill_pattern"]


def test_vulnerable_pattern_without_kill_signal_remains():
    entry = _reentrancy_summary(UNGUARDED_WITHDRAW)
    assert entry["match_count"] >= 1
    assert entry["suppressed_count"] == 0


def test_kill_signal_is_scoped_to_its_function_not_global():
    # Guarded withdraw suppressed, unguarded withdraw2 in the same file kept.
    code = """
contract V {
    mapping(address=>uint) public balances;
    function withdraw(uint a) external nonReentrant {
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        balances[msg.sender] = 0;
    }
    function withdraw2(uint a) external {
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""
    entry = _reentrancy_summary(code)
    assert entry["match_count"] == 1
    assert entry["suppressed_count"] == 1
    assert entry["matches"][0]["line"] > entry["suppressions"][0]["line"]


def test_kill_signal_whitespace_normalization():
    code = GUARDED_WITHDRAW.replace("external nonReentrant", "external    nonReentrant")
    entry = _reentrancy_summary(code)
    assert entry["match_count"] == 0
    assert entry["suppressed_count"] == 1


def test_kill_signal_does_not_suppress_other_classes():
    # Same call line: reentrancy is killed by nonReentrant, but the
    # unchecked-return-value match (no require(success)) must survive.
    code = """
contract V {
    mapping(address=>uint) public balances;
    function withdraw(uint a) external nonReentrant {
        msg.sender.call{value: a}("");
        balances[msg.sender] = 0;
    }
}
"""
    summary = {e["class"]: e for e in bug_detector.get_summary(code)}
    assert summary["reentrancy"]["suppressed_count"] >= 1
    assert summary["unchecked_return_value"]["match_count"] >= 1


def test_kill_patterns_are_auditable_and_prose_only_signals_do_not_suppress():
    # off_by_one has no machine kill patterns: a boundary match is never
    # suppressed by prose about unit tests.
    assert bug_detector.get_kill_patterns("off_by_one") == []
    assert bug_detector.get_kill_patterns("reentrancy")
    code = "contract V { function f(uint t) external { if (t > 10) {} } uint x; for (uint i = 0; i <= 5; i++) {} }"
    # At least the kill-pattern API itself is defined; suppression must
    # come from a machine pattern, never from prose alone.
    for entry in bug_detector.get_summary(code):
        for sup in entry["suppressions"]:
            assert sup["kill_pattern"]


# ---------------------------------------------------------------- #23
def test_ai_safe_uniform_guards_not_reported():
    for guard in ("nonReentrant", "onlyOwner"):
        code = f"""
contract V {{
    uint public bal;
    function a(uint x) external {guard} {{ bal += x; }}
    function b(uint x) external {guard} {{ bal -= x; }}
}}
"""
        assert ai_tools.check_ai_vulnerabilities(code) == []


def test_ai_uniformly_unguarded_is_not_inconsistency():
    code = """
contract V {
    uint public bal;
    function a(uint x) external { bal += x; }
    function b(uint x) external { bal -= x; }
}
"""
    assert ai_tools.check_ai_vulnerabilities(code) == []


def test_ai_mixed_guards_confirmed_with_evidence():
    code = """
contract V {
    uint public bal;
    function a(uint x) external nonReentrant { bal += x; }
    function b(uint x) external { bal -= x; }
}
"""
    findings = ai_tools.check_ai_vulnerabilities(code)
    assert len(findings) == 1
    f = findings[0]
    assert f["status"] == "confirmed"
    assert f["confidence"] == "high"
    assert "bal" in f["name"]
    guards = {ev["function"]: ev["guard"] for ev in f["evidence"]}
    assert guards["a"]["nonReentrant"] is True
    assert guards["b"]["nonReentrant"] is False
    assert all("line" in ev and "content" in ev for ev in f["evidence"])


def test_ai_role_granted_per_role_not_per_file():
    code = """
contract R {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    function init() external { grantRole(MINTER_ROLE, msg.sender); }
}
"""
    findings = ai_tools.check_ai_vulnerabilities(code)
    assert len(findings) == 1
    assert "ADMIN_ROLE" in findings[0]["description"]
    assert "MINTER_ROLE" not in findings[0]["description"]
    assert findings[0]["status"] == "confirmed"
    assert findings[0]["evidence"][0]["role"] == "ADMIN_ROLE"


def test_ai_heuristic_only_code_produces_no_confirmed_finding():
    code = """
/// @notice Does things
/// @param x input
/// @return out output
contract V {
    function f(uint x) external returns (uint out) {
        require(x > 0);
        require(x < 100);
        require(x != 7);
        out = x;
    }
}
"""
    assert ai_tools.check_ai_vulnerabilities(code) == []
    report = ai_tools.format_ai_findings(ai_tools.detect_ai_generated(code), [])
    assert "checklist only, NOT findings" in report


# ---------------------------------------------------------------- #24
VULN_ZK = """
contract V {
    mapping(address=>uint) public balances;
    function withdraw(uint a) external {
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        balances[msg.sender] = 0;
    }
    function set(uint x) public { balances[msg.sender] = x; }
}
"""

SAFE_ZK = """
contract S {
    mapping(address=>uint) public balances;
    function withdraw(uint a) external onlyOwner nonReentrant {
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
    }
    function set(uint x) public onlyOwner { balances[msg.sender] = x; }
}
"""


def test_zksync_vulnerable_cei_and_unguarded_function_confirmed():
    r = zksync_detector.check_vulnerable_patterns(VULN_ZK)
    assert r["vulnerable_patterns_found"]
    cei = r["vulnerable_patterns_found"][0]
    assert cei["status"] == "confirmed"
    assert cei["function"] == "withdraw"
    assert "evidence" in cei
    ids = [v["id"] for v in r["attack_vectors"]]
    assert 6 in ids  # unguarded public function
    assert r["attack_vectors_applicable"] == len(r["attack_vectors"])


def test_zksync_safe_fixture_not_confirmed():
    r = zksync_detector.check_vulnerable_patterns(SAFE_ZK)
    assert r["vulnerable_patterns_found"] == []
    assert r["attack_vectors_applicable"] == 0
    assert r["estimated_hardenability"] == "high"


def test_zksync_v20_confirmed_only_via_call_before_write():
    code = """
import {ReentrancyGuard} from "x";
contract V {
    mapping(address=>uint) public balances;
    function withdraw(uint a) external {
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""
    r = zksync_detector.check_vulnerable_patterns(code)
    ids = [v["id"] for v in r["attack_vectors"]]
    assert 20 in ids


def test_zksync_defensive_fee_token_not_confirmed():
    code = """
contract V {
    function transfer(address to, uint amount) external {
        if (amount != _amount) revert TokensWithFeesNotSupported();
        token.transfer(to, amount);
    }
}
"""
    r = zksync_detector.check_vulnerable_patterns(code)
    ids = [v["id"] for v in r["attack_vectors"]]
    assert 7 not in ids
    assert 7 in [v["id"] for v in r["attack_vectors_defensive"]]


def test_zksync_mere_presence_is_not_confirmed():
    # abi.encode used in a guarded function, no version discriminator:
    # trigger present, precondition not established -> presence_only.
    code = """
contract M {
    function f(bytes memory x) public onlyOwner returns (bytes memory) {
        return abi.encode(x);
    }
}
"""
    r = zksync_detector.check_vulnerable_patterns(code)
    assert r["attack_vectors_applicable"] == 0
    assert 16 in [v["id"] for v in r["attack_vectors_presence_only"]]
    for v in r["attack_vectors_presence_only"]:
        assert v["status"] == "presence_only"


def test_zksync_report_separates_confirmed_from_presence_only():
    r = zksync_detector.check_vulnerable_patterns(SAFE_ZK)
    report = zksync_detector.format_zksync_report(r)
    assert "Confirmed Applicable Attack Vectors" in report
    assert "Presence only (NOT confirmed findings)" in report
    assert "on confirmed findings only" in report
