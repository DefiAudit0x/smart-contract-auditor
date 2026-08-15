// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./interfaces/IPriceFeed.sol";
import "./interfaces/ITokenPriceFeed.sol";

interface ITellorFeed {
    function getCurrentValue(bytes32 _queryId) external view returns (bytes calldata _value);
}

contract TellorPriceFeed is IPriceFeed {
    ITellorFeed public immutable oracle;
    address public immutable override token;
    bytes32 public immutable queryId;

    constructor(
        address _oracle,
        address _token,
        bytes32 _queryId
    ) {
        require(_oracle != address(0x0), "e2637b _oracle must not be address 0x0");
        require(_token != address(0x0), "e2637b _token must not be address 0x0");
        require(_queryId.length > 0, "e2637b _queryId must not be 0 length");
        token = _token;
        oracle = ITellorFeed(_oracle);
        queryId = _queryId;
    }

    function price() public view virtual override returns (uint256) {
        return uint256(bytes32(oracle.getCurrentValue(queryId)));
    }

    function pricePoint() public view override returns (uint256) {
        return price();
    }

    function emitPriceSignal() public override {
        emit PriceUpdate(token, price(), price());
    }
}
