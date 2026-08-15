// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity ^0.6.0;
contract HistoricalAssemblySuicide {
    function destroy(address payable _to) public {
        assembly { suicide(_to) }
    }
}
