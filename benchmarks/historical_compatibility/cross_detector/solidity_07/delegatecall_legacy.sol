// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.7.0;
contract CrossDetectorDelegatecallLegacy {
    address public implementation;
    constructor(address _implementation) public {
        implementation = _implementation;
    }
    function execute(bytes memory data) public {
        implementation.callcode(data);
    }
}
