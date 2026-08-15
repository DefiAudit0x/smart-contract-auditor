// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.5.0;
contract CrossDetectorTimestampLegacy {
    function claim() public view returns (bool) {
        return now > 0;
    }
}
