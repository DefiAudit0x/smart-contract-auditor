// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.6.0;
contract CrossDetectorSelfdestructLegacy {
    function destroy(address payable _to) public {
        suicide(_to);
    }
}
