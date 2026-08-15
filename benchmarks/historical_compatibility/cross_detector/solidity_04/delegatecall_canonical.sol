// Measurement-only Cross-Detector Compatibility corpus. No production detector is modified.
pragma solidity ^0.4.9;
contract CrossDetectorDelegatecallCanonical {
    address public implementation;
    function CrossDetectorDelegatecallCanonical(address _implementation) public {
        implementation = _implementation;
    }
    function execute(bytes memory data) public {
        implementation.delegatecall(data);
    }
}
