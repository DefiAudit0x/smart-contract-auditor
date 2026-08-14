// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract DelegatecallImplementation {
    uint256 public value;

    function setValue(uint256 newValue) external {
        value = newValue;
    }
}

contract DelegatecallProxy {
    uint256 public value;

    fallback() external payable {
        address implementation = address(0);
        assembly {
            implementation := sload(1)
        }
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "delegatecall failed");
    }

    function setImplementation(address implementation) external {
        assembly {
            sstore(1, implementation)
        }
    }
}

contract DelegatecallPoC {
    function testPoC_DelegatecallChangesProxyStorage() external {
        DelegatecallImplementation implementation = new DelegatecallImplementation();
        DelegatecallProxy proxy = new DelegatecallProxy();
        proxy.setImplementation(address(implementation));
        (bool success, ) = address(proxy).call(
            abi.encodeWithSignature("setValue(uint256)", 42)
        );
        require(success, "proxy call failed");
        require(proxy.value() == 42, "proxy storage was not changed");
        require(implementation.value() == 0, "implementation storage changed unexpectedly");
    }
}
