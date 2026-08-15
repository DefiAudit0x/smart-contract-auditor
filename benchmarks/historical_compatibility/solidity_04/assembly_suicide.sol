// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity ^0.4.9;
contract HistoricalAssemblySuicide {
    function destroy(address _to) public {
        assembly { suicide(_to) }
    }
}
