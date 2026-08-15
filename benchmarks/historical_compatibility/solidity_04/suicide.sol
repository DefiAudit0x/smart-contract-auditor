// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity ^0.4.9;
contract HistoricalSuicide {
    function destroy(address _to) public {
        suicide(_to);
    }
}
