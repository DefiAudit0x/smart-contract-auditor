// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity ^0.6.0;
contract HistoricalFixed {
    bool public closed;
    function close() public {
        closed = true;
    }
}
