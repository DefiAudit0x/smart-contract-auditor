// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity 0.8.25;
contract CrossDetectorSelfdestructFixed {
    bool public closed;
    function close() public {
        closed = true;
    }
}
