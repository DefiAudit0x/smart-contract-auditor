// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.7.0;
contract CrossDetectorTimestampCanonical {
    function claim() public view returns (bool) {
        return block.timestamp > 0;
    }
}
