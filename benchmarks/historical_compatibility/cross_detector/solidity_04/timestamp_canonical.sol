// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.4.9;
contract CrossDetectorTimestampCanonical {
    function claim() public constant returns (bool) {
        return block.timestamp > 0;
    }
}
