// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity ^0.7.0;
contract HistoricalSelfdestruct {
    function destroy(address payable _to) public {
        selfdestruct(_to);
    }
}
