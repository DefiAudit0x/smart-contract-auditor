// Measurement-only historical compatibility corpus. No production detector is modified.
pragma solidity 0.8.25;
contract HistoricalFixed {
    bool public closed;
    function close() public {
        closed = true;
    }
}
