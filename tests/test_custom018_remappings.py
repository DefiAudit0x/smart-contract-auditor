import pytest

from mcp_integration import scan_swc_patterns


def _initializer_source(import_path):
    return f'''import {{Initializable}} from "{import_path}";
contract C is Initializable {{
    function initialize() external initializer {{}}
}}'''


def _reports_custom_018(code, **kwargs):
    return any(
        finding["id"] == "CUSTOM-018"
        for finding in scan_swc_patterns(code, **kwargs)
    )


@pytest.mark.parametrize(
    "target",
    [
        "lib/openzeppelin-contracts-upgradeable/contracts/",
        "lib/openzeppelin-contracts/contracts/",
        "node_modules/@openzeppelin/contracts-upgradeable/",
        "node_modules/@openzeppelin/contracts/",
    ],
)
def test_explicit_alias_remapping_to_allowlisted_oz_path_is_trusted(target):
    code = _initializer_source("oz/proxy/utils/Initializable.sol")

    assert not _reports_custom_018(code, remappings=[f"oz/={target}"])


def test_alias_import_without_explicit_remapping_is_reported():
    code = _initializer_source("oz/proxy/utils/Initializable.sol")

    assert _reports_custom_018(code)


def test_canonical_import_redirected_to_local_code_is_reported():
    code = _initializer_source(
        "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol"
    )

    assert _reports_custom_018(
        code,
        remappings=["@openzeppelin/=src/mocks/"],
    )


def test_longest_matching_prefix_selects_the_canonical_dependency():
    code = _initializer_source(
        "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol"
    )

    assert not _reports_custom_018(
        code,
        remappings=[
            "@openzeppelin/=src/mocks/",
            "@openzeppelin/contracts-upgradeable/="
            "lib/openzeppelin-contracts-upgradeable/contracts/",
        ],
    )


def test_longest_context_precedes_the_prefix_candidate():
    code = _initializer_source("oz/proxy/utils/Initializable.sol")

    assert _reports_custom_018(
        code,
        remappings=[
            "src/:oz/=lib/openzeppelin-contracts-upgradeable/contracts/",
            "src/Example.sol:oz/=src/mocks/",
        ],
        source_unit_name="src/Example.sol",
    )


def test_nonmatching_prefix_does_not_shadow_a_shorter_context_rule():
    code = _initializer_source("oz/proxy/utils/Initializable.sol")

    assert not _reports_custom_018(
        code,
        remappings=[
            "src/:oz/=lib/openzeppelin-contracts-upgradeable/contracts/",
            "src/Example.sol:unused/=src/mocks/",
        ],
        source_unit_name="src/Example.sol",
    )


def test_longest_prefix_wins_after_context_length_ties():
    code = _initializer_source("oz/proxy/utils/Initializable.sol")

    assert not _reports_custom_018(
        code,
        remappings=[
            "src/:oz/=src/mocks/",
            "src/:oz/proxy/="
            "lib/openzeppelin-contracts-upgradeable/contracts/proxy/",
        ],
        source_unit_name="src/Example.sol",
    )


def test_direct_canonical_import_is_resolved_through_supplied_remappings():
    code = _initializer_source(
        "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol"
    )

    assert not _reports_custom_018(
        code,
        remappings=[
            "@openzeppelin/contracts-upgradeable/="
            "lib/openzeppelin-contracts-upgradeable/contracts/",
        ],
    )


def test_noncanonical_duplicate_binding_blocks_suppression():
    code = '''import {Initializable as OZInit} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {FakeInit as OZInit} from "local/FakeInitializable.sol";
contract C is OZInit { function initialize() external initializer {} }'''

    assert _reports_custom_018(code)


def test_untrusted_bare_import_blocks_canonical_suppression():
    code = '''import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "local/Other.sol";
contract C is Initializable { function initialize() external initializer {} }'''

    assert _reports_custom_018(code)


def test_namespace_import_does_not_trust_unqualified_initializable():
    code = '''import * as OZ from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
contract C is Initializable { function initialize() external initializer {} }'''

    assert _reports_custom_018(code)


def test_malformed_remapping_metadata_disables_direct_path_suppression():
    code = _initializer_source(
        "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol"
    )

    assert _reports_custom_018(code, remappings=["not-a-remapping"])


def test_contextual_remapping_requires_matching_exact_source_unit_name():
    code = _initializer_source("oz/proxy/utils/Initializable.sol")
    mapping = ["src/:oz/=lib/openzeppelin-contracts-upgradeable/contracts/"]

    assert not _reports_custom_018(
        code,
        remappings=mapping,
        source_unit_name="src/Example.sol",
    )
    assert _reports_custom_018(code, remappings=mapping)
    assert _reports_custom_018(
        code,
        remappings=mapping,
        source_unit_name="test/Example.sol",
    )


@pytest.mark.parametrize(
    "source_unit_name",
    ["src/../Example.sol", "src/ Example.sol", 123],
)
def test_malformed_source_unit_name_fails_closed(source_unit_name):
    code = _initializer_source("oz/proxy/utils/Initializable.sol")

    assert _reports_custom_018(
        code,
        remappings=["src/:oz/=lib/openzeppelin-contracts-upgradeable/contracts/"],
        source_unit_name=source_unit_name,
    )


def test_context_matching_does_not_normalize_source_unit_names():
    code = _initializer_source("oz/proxy/utils/Initializable.sol")

    assert _reports_custom_018(
        code,
        remappings=["src/Example.sol:oz/="
                    "lib/openzeppelin-contracts-upgradeable/contracts/"],
        source_unit_name="src//Example.sol",
    )


def test_conflicting_equally_specific_remappings_fail_closed():
    code = _initializer_source("oz/proxy/utils/Initializable.sol")

    assert _reports_custom_018(
        code,
        remappings=[
            "oz/=lib/openzeppelin-contracts-upgradeable/contracts/",
            "oz/=src/mocks/",
        ],
    )


def test_identical_equally_specific_remappings_to_same_target_are_not_conflicting():
    code = _initializer_source("oz/proxy/utils/Initializable.sol")
    mapping = "oz/=lib/openzeppelin-contracts-upgradeable/contracts/"

    assert not _reports_custom_018(code, remappings=[mapping, mapping])


@pytest.mark.parametrize(
    "remappings",
    [
        ["=lib/openzeppelin-contracts-upgradeable/contracts/"],
        ["oz/=lib/openzeppelin-contracts-upgradeable/contracts/../../src/"],
        ["oz/=https://example.invalid/"],
        ["oz/=lib/openzeppelin-contracts-upgradeable/contracts/=extra"],
        ["src::Example.sol:oz/=lib/openzeppelin-contracts-upgradeable/contracts/"],
        "oz/=lib/openzeppelin-contracts-upgradeable/contracts/",
    ],
)
def test_malformed_or_unsafe_remapping_metadata_fails_closed(remappings):
    code = _initializer_source("oz/proxy/utils/Initializable.sol")

    assert _reports_custom_018(code, remappings=remappings)


def test_import_traversal_is_not_resolved_to_a_trusted_dependency():
    code = _initializer_source("oz/../proxy/utils/Initializable.sol")

    assert _reports_custom_018(
        code,
        remappings=["oz/=lib/openzeppelin-contracts-upgradeable/contracts/"],
    )


def test_case_mismatched_remapped_filename_is_not_trusted():
    code = _initializer_source("oz/proxy/utils/INITIALIZABLE.sol")

    assert _reports_custom_018(
        code,
        remappings=["oz/=lib/openzeppelin-contracts-upgradeable/contracts/"],
    )


def test_prefix_collision_does_not_match_a_directory_prefix():
    code = _initializer_source("oz-fake/proxy/utils/Initializable.sol")

    assert _reports_custom_018(
        code,
        remappings=["oz/=lib/openzeppelin-contracts-upgradeable/contracts/"],
    )


def test_remapping_prefix_uses_raw_solidity_string_prefix_semantics():
    code = _initializer_source("ozproxy/utils/Initializable.sol")

    assert not _reports_custom_018(
        code,
        remappings=["oz=lib/openzeppelin-contracts-upgradeable/contracts/"],
    )


def test_canonical_path_text_in_comment_cannot_override_real_import_path():
    code = '''import {Initializable} /* from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol" */ from "local/FakeInitializable.sol";
contract C is Initializable { function initialize() external initializer {} }'''

    assert _reports_custom_018(code)


def test_contextual_redirect_without_source_unit_does_not_trust_direct_import():
    code = _initializer_source(
        "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol"
    )

    assert _reports_custom_018(
        code,
        remappings=["src/:@openzeppelin/=src/mocks/"],
    )
