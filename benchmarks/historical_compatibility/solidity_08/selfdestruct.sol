// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity 0.8.25;
contract HistoricalSelfdestruct {
    function destroy(address payable _to) public {
        selfdestruct(_to);
    }
}
