// Read-only boundary probe; not a production or incident source.
pragma solidity ^0.4.9;
contract MinimalHistoricalSuicide {
    function destroy(address _to) public {
        suicide(_to);
    }
}
