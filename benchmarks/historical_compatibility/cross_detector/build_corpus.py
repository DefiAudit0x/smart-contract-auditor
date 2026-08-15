from pathlib import Path

ROOT = Path(__file__).resolve().parent

VERSIONS = {
    "solidity_04": {"pragma": "^0.4.9", "address_type": "address"},
    "solidity_05": {"pragma": "^0.5.0", "address_type": "address payable"},
    "solidity_06": {"pragma": "^0.6.0", "address_type": "address payable"},
    "solidity_07": {"pragma": "^0.7.0", "address_type": "address payable"},
    "solidity_08": {"pragma": "0.8.25", "address_type": "address payable"},
}

HEADER = "// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.\n"


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HEADER + body, encoding="utf-8")


for version, cfg in VERSIONS.items():
    directory = ROOT / version
    pragma = cfg["pragma"]
    address_type = cfg["address_type"]
    read_modifier = "constant" if version == "solidity_04" else "view"
    constructor_canonical = (
        "function CrossDetectorDelegatecallCanonical(address _implementation) public"
        if version == "solidity_04"
        else "constructor(address _implementation) public"
    )
    constructor_legacy = (
        "function CrossDetectorDelegatecallLegacy(address _implementation) public"
        if version == "solidity_04"
        else "constructor(address _implementation) public"
    )
    constructor_fixed = (
        "function CrossDetectorDelegatecallFixed(address _implementation) public"
        if version == "solidity_04"
        else "constructor(address _implementation) public"
    )

    write(
        directory / "selfdestruct_canonical.sol",
        f'''pragma solidity {pragma};
contract CrossDetectorSelfdestructCanonical {{
    function destroy({address_type} _to) public {{
        selfdestruct(_to);
    }}
}}
''',
    )
    write(
        directory / "selfdestruct_legacy.sol",
        f'''pragma solidity {pragma};
contract CrossDetectorSelfdestructLegacy {{
    function destroy({address_type} _to) public {{
        suicide(_to);
    }}
}}
''',
    )
    write(
        directory / "selfdestruct_fixed.sol",
        f'''pragma solidity {pragma};
contract CrossDetectorSelfdestructFixed {{
    bool public closed;
    function close() public {{
        closed = true;
    }}
}}
''',
    )

    write(
        directory / "timestamp_canonical.sol",
        f'''pragma solidity {pragma};
contract CrossDetectorTimestampCanonical {{
    function claim() public {read_modifier} returns (bool) {{
        return block.timestamp > 0;
    }}
}}
''',
    )
    write(
        directory / "timestamp_legacy.sol",
        f'''pragma solidity {pragma};
contract CrossDetectorTimestampLegacy {{
    function claim() public {read_modifier} returns (bool) {{
        return now > 0;
    }}
}}
''',
    )
    write(
        directory / "timestamp_fixed.sol",
        f'''pragma solidity {pragma};
contract CrossDetectorTimestampFixed {{
    bool public enabled;
    function claim() public {read_modifier} returns (bool) {{
        return enabled;
    }}
}}
''',
    )

    write(
        directory / "delegatecall_canonical.sol",
        f'''pragma solidity {pragma};
contract CrossDetectorDelegatecallCanonical {{
    address public implementation;
    {constructor_canonical} {{
        implementation = _implementation;
    }}
    function execute(bytes memory data) public {{
        implementation.delegatecall(data);
    }}
}}
''',
    )
    write(
        directory / "delegatecall_legacy.sol",
        f'''pragma solidity {pragma};
contract CrossDetectorDelegatecallLegacy {{
    address public implementation;
    {constructor_legacy} {{
        implementation = _implementation;
    }}
    function execute(bytes memory data) public {{
        implementation.callcode(data);
    }}
}}
''',
    )
    write(
        directory / "delegatecall_fixed.sol",
        f'''pragma solidity {pragma};
contract CrossDetectorDelegatecallFixed {{
    address public implementation;
    {constructor_fixed} {{
        implementation = _implementation;
    }}
    function execute(bytes memory data) public {{
        implementation.call(data);
    }}
}}
''',
    )
