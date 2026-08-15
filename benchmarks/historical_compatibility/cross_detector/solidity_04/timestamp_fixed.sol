// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.4.9;
contract CrossDetectorTimestampFixed {
    bool public enabled;
    function claim() public constant returns (bool) {
        return enabled;
    }
}
