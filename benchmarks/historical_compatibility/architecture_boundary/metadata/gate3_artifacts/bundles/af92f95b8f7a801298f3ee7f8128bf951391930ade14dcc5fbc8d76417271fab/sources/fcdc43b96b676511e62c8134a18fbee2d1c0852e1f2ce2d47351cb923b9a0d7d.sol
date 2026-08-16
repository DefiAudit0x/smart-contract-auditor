pragma solidity ^0.8.25;

contract ImportedLibraryTarget {
    function destroyImported() external {
        selfdestruct(payable(msg.sender));
    }
}
