// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity ^0.4.9;
contract HistoricalAssemblySelfdestruct {
    function destroy(address _to) public {
        assembly { selfdestruct(_to) }
    }
}
