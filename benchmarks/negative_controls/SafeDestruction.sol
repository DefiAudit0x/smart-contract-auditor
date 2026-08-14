// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract SafeDestruction {
    bool public closed;

    function close() external {
        closed = true;
    }
}
