// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

interface Vm {
    function deal(address who, uint256 newBalance) external;
}

contract SelfdestructVictim {
    constructor() payable {}

    function destroy(address payable recipient) external {
        selfdestruct(recipient);
    }
}

contract SelfdestructPoC {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testPoC_SelfdestructForcesBalanceTransfer() external {
        vm.deal(address(this), 1 ether);
        SelfdestructVictim victim = new SelfdestructVictim{value: 1 ether}();
        uint256 beforeBalance = address(this).balance;
        victim.destroy(payable(address(this)));
        require(address(this).balance == beforeBalance + 1 ether, "selfdestruct effect missing");
    }
}
