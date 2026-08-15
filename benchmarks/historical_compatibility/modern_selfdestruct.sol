// Read-only architecture boundary probe. Not a production fixture.
pragma solidity 0.8.25;
contract BoundaryModernSelfdestruct {
    function destroy(address payable recipient) external {
        selfdestruct(recipient);
    }
}
