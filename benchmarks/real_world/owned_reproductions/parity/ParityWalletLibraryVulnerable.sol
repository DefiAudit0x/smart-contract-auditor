// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Minimal owned model of the November 2017 Parity shared-library failure.
/// @dev The historical source spells selfdestruct as `suicide` under Solidity 0.4.x.
contract ParityWalletLibraryVulnerable {
    mapping(address => bool) public owner;
    bool public initialized;

    /// @notice The shared library was deployed without calling this initializer.
    function initWallet(address newOwner) external {
        require(!initialized, "already initialized");
        owner[newOwner] = true;
        initialized = true;
    }

    /// @notice A newly acquired library owner can destroy shared code.
    function kill(address payable recipient) external {
        require(owner[msg.sender], "not owner");
        selfdestruct(recipient);
    }
}
