// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity 0.8.25;
contract CrossDetectorTimestampCanonical {
    function claim() public view returns (bool) {
        return block.timestamp > 0;
    }
}
