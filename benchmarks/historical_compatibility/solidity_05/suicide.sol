// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity ^0.5.0;
contract HistoricalSuicide {
    function destroy(address payable _to) public {
        suicide(_to);
    }
}
