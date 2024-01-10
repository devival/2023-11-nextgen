# Original link
https://github.com/code-423n4/2023-10-nextgen-findings/issues/1893
# Lines of code

https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/AuctionDemo.sol#L112-L114


# Vulnerability details

## Impact
Sending the highest bid to the auction contract owner poses a centralization risk. Owners of auctioned tokens would have to rely solely on trust to auctionDemo contract owners to get the funds.

## Proof of Concept
According to the scope description of `AuctionDemo.sol`: “The auctionDemo smart contract holds the current auctions after the `mintAndAuction` functionality is called. Users can bid on a token, and the highest bidder can claim the token after an auction finishes.” Below is a withdrawal part of `claimAuction` function, which has `auctionDemo.owner()` as a receiver of the funds:

```solidity
File: smart-contracts/AuctionDemo.sol                
112: 		    IERC721(gencore).safeTransferFrom(ownerOfToken, highestBidder, _tokenid);

113: 		    (bool success, ) = payable(owner()).call{value: highestBid}("");

114: 		    emit ClaimAuction(owner(), _tokenid, success, highestBid);

```
[AuctionDemo.sol#L112-L114](https://github.com/code-423n4/2023-10-nextgen/blob/8b518196629faa37eae39736837b24926fd3c07c/smart-contracts/AuctionDemo.sol#L112-L114)

## Tools Used
Manual Review

## Recommended Mitigation Steps
Send the funds to the actual token holder to make the auction process trustless. Replace the receiver `owner()` in `claimAuction`:

```solidity
File: smart-contracts/AuctionDemo.sol                

113: 		    (bool success, ) = payable(owner()).call{value: highestBid}("");

114: 		    emit ClaimAuction(owner(), _tokenid, success, highestBid);

```

with: 
```solidity
File: smart-contracts/AuctionDemo.sol                

113: 		    (bool success, ) = payable(ownerOfToken).call{value: highestBid}("");

114: 		    emit ClaimAuction(ownerOfToken, _tokenid, success, highestBid);

```


## Assessed type

ETH-Transfer