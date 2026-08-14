// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract UncheckedPayout {
    function pay(address payable recipient, uint256 amount) external {
        recipient.send(amount);
    }

    receive() external payable {}
}

contract RejectingReceiver {
    receive() external payable {
        revert("reject");
    }
}

contract UncheckedTransferPoC {
    function testPoC_FailedTransferIsIgnored() external {
        UncheckedPayout payout = new UncheckedPayout();
        RejectingReceiver receiver = new RejectingReceiver();
        (bool funded, ) = address(payout).call{value: 1}('');
        require(funded, "funding failed");
        (bool success, ) = address(payout).call(
            abi.encodeWithSignature("pay(address,uint256)", address(receiver), 1)
        );
        require(success, "unchecked transfer unexpectedly reverted");
        require(address(payout).balance == 1, "failed payment was not retained");
    }
}
