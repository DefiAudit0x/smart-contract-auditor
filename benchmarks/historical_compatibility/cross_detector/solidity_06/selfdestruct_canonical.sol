// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.6.0;
contract CrossDetectorSelfdestructCanonical {
    function destroy(address payable _to) public {
        selfdestruct(_to);
    }
}
