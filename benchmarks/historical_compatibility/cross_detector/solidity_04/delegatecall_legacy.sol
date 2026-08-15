// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.4.9;
contract CrossDetectorDelegatecallLegacy {
    address public implementation;
    function CrossDetectorDelegatecallLegacy(address _implementation) public {
        implementation = _implementation;
    }
    function execute(bytes memory data) public {
        implementation.callcode(data);
    }
}
