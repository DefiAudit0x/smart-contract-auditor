// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract UnboundedDistributor {
    address payable[] public recipients;

    function addRecipient(address payable recipient) external {
        recipients.push(recipient);
    }

    function distribute(uint256 amount) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            recipients[i].transfer(amount);
        }
    }

    receive() external payable {}
}

contract UnboundedLoopPoC {
    function testPoC_DistributionScalesWithArray() external {
        UnboundedDistributor distributor = new UnboundedDistributor();
        distributor.addRecipient(payable(address(0x1001)));
        distributor.addRecipient(payable(address(0x1002)));
        (bool funded, ) = address(distributor).call{value: 2}('');
        require(funded, "funding failed");
        distributor.distribute(1);
        require(address(distributor).balance == 0, "distribution did not iterate recipients");
    }
}
