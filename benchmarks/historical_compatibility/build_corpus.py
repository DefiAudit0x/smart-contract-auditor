from pathlib import Path

ROOT = Path(__file__).resolve().parent

TEMPLATES = {
    "solidity_04": {
        "pragma": "^0.4.9",
        "address_type": "address",
        "cast": "",
        "selfdestruct": "selfdestruct(_to);",
        "suicide": "suicide(_to);",
        "assembly_selfdestruct": "assembly { selfdestruct(_to) }",
        "assembly_suicide": "assembly { suicide(_to) }",
    },
    "solidity_05": {
        "pragma": "^0.5.0",
        "address_type": "address payable",
        "cast": "payable(_to)",
        "selfdestruct": "selfdestruct(_to);",
        "suicide": "suicide(_to);",
        "assembly_selfdestruct": "assembly { selfdestruct(_to) }",
        "assembly_suicide": "assembly { suicide(_to) }",
    },
    "solidity_06": {
        "pragma": "^0.6.0",
        "address_type": "address payable",
        "cast": "payable(_to)",
        "selfdestruct": "selfdestruct(_to);",
        "suicide": "suicide(_to);",
        "assembly_selfdestruct": "assembly { selfdestruct(_to) }",
        "assembly_suicide": "assembly { suicide(_to) }",
    },
    "solidity_07": {
        "pragma": "^0.7.0",
        "address_type": "address payable",
        "cast": "payable(_to)",
        "selfdestruct": "selfdestruct(_to);",
        "suicide": "suicide(_to);",
        "assembly_selfdestruct": "assembly { selfdestruct(_to) }",
        "assembly_suicide": "assembly { suicide(_to) }",
    },
    "solidity_08": {
        "pragma": "0.8.25",
        "address_type": "address payable",
        "cast": "payable(_to)",
        "selfdestruct": "selfdestruct(_to);",
        "suicide": "suicide(_to);",
        "assembly_selfdestruct": "assembly { selfdestruct(_to) }",
        "assembly_suicide": "assembly { suicide(_to) }",
    },
}

HEADER = "// Measurement-only historical compatibility corpus. No production detector is modified.\n"


def write_contract(directory: Path, filename: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / filename).write_text(HEADER + body, encoding="utf-8")


for version, cfg in TEMPLATES.items():
    directory = ROOT / version
    pragma = cfg["pragma"]
    address_type = cfg["address_type"]
    cast = cfg["cast"]
    write_contract(
        directory,
        "selfdestruct.sol",
        f'''pragma solidity {pragma};
contract HistoricalSelfdestruct {{
    function destroy({address_type} _to) public {{
        {cfg["selfdestruct"]}
    }}
}}
''',
    )
    write_contract(
        directory,
        "suicide.sol",
        f'''pragma solidity {pragma};
contract HistoricalSuicide {{
    function destroy({address_type} _to) public {{
        {cfg["suicide"]}
    }}
}}
''',
    )
    write_contract(
        directory,
        "assembly_selfdestruct.sol",
        f'''pragma solidity {pragma};
contract HistoricalAssemblySelfdestruct {{
    function destroy({address_type} _to) public {{
        assembly {{ selfdestruct(_to) }}
    }}
}}
''',
    )
    write_contract(
        directory,
        "assembly_suicide.sol",
        f'''pragma solidity {pragma};
contract HistoricalAssemblySuicide {{
    function destroy({address_type} _to) public {{
        assembly {{ suicide(_to) }}
    }}
}}
''',
    )
    write_contract(
        directory,
        "fixed.sol",
        f'''pragma solidity {pragma};
contract HistoricalFixed {{
    bool public closed;
    function close() public {{
        closed = true;
    }}
}}
''',
    )
