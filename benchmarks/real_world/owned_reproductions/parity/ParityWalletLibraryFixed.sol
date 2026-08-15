// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Minimal fixed contrast for the Parity shared-library failure.
/// @dev Initialization is completed at deployment and the destructive path is removed.
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
