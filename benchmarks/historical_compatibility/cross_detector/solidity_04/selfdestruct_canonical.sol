// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.4.9;
contract CrossDetectorSelfdestructCanonical {
    function destroy(address _to) public {
        selfdestruct(_to);
    }
}
