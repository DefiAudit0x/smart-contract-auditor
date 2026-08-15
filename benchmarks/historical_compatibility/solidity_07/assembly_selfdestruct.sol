// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity ^0.7.0;
contract HistoricalAssemblySelfdestruct {
    function destroy(address payable _to) public {
        assembly { selfdestruct(_to) }
    }
}
