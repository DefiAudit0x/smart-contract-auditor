// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.6.0;
contract CrossDetectorSelfdestructFixed {
    bool public closed;
    function close() public {
        closed = true;
    }
}
