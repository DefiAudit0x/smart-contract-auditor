// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract BatchDosLoop {
    address payable[] public recipients;

    function addRecipient(address payable recipient) external {
        recipients.push(recipient);
    }

    function distributeAll(uint256 amount) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            recipients[i].transfer(amount);
        }
    }

    receive() external payable {}
}

contract BatchDosLoopPoC {
    function testPoC_LoopProcessesAttackerInflatedList() external {
        BatchDosLoop distributor = new BatchDosLoop();
        distributor.addRecipient(payable(address(0x1001)));
        distributor.addRecipient(payable(address(0x1002)));
        distributor.addRecipient(payable(address(0x1003)));
        (bool funded, ) = address(distributor).call{value: 3}("");
        require(funded, "funding failed");
        distributor.distributeAll(1);
        require(address(distributor).balance == 0, "loop did not process all recipients");
    }
}
