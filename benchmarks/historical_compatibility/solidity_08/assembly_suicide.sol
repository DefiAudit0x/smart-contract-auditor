// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity 0.8.25;
contract HistoricalAssemblySuicide {
    function destroy(address payable _to) public {
        assembly { suicide(_to) }
    }
}
