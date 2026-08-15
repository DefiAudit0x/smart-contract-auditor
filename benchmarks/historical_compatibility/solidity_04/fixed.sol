// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity ^0.4.9;
contract HistoricalFixed {
    bool public closed;
    function close() public {
        closed = true;
    }
}
