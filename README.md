# Medium Risk Reports

## 1. [M-01] Use `safeTransferFrom` Instead of `transferFrom` for `ERC721`. - Use of `transferFrom()` rather than `safeTransferFrom()` for NFTs in will lead to the loss of NFTs.

_Use of `transferFrom` method for ERC721 transfer is discouraged and recommended to use `safeTransferFrom` whenever possible by OpenZeppelin.
This is because `transferFrom()` cannot check whether the receiving address know how to handle ERC721 tokens._

Example:
In the function shown at below PoC, ERC721 token is sent to `msg.sender` with the `transferFrom` method.
If this `msg.sender` is a contract and is not aware of incoming ERC721 tokens, the sent token could be locked up in the contract forever.

```java
236:     ERC721(o.collection).transferFrom(o.signer, receiver, o.tokenId);
```

Recommended Mitigation Steps:

-   I recommend to call the `safeTransferFrom()` method instead of `transferFrom()` for NFT transfers.

<br>
<hr>

## 2. [M-02] `VoteEscrowCore.safeTransferFrom` does not check correct magic bytes returned from receiver contract’s `onERC721Received` function

_While `VoteEscrowCore.safeTransferFrom` does try to call `onERC721Received` on the receiver it does not check the for the required “magic bytes” which is `IERC721.onERC721received.selector` in this case. See [OpenZeppelin docs](https://docs.openzeppelin.com/contracts/3.x/api/token/erc721#IERC721Receiver-onERC721Received-address-address-uint256-bytes-) for more information._

[ERC721.sol#L395-L417](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/ce0068c21ecd97c6ec8fb0db08570f4b43029dde/contracts/token/ERC721/ERC721.sol#L395-L417)

_It’s quite possible that a call to `onERC721Received` could succeed because the contract had a `fallback` function implemented, but the contract is not ERC721 compliant._

_The impact is that NFT tokens may be sent to non-compliant contracts and lost._

Example:

```java
try IERC721Receiver(_to).onERC721Received(msg.sender, _from, _tokenId, _data) returns (bytes4) {} catch (
    bytes memory reason
```

[but they should be:](https://github.com/golom-protocol/contracts/commit/19ba6e83892e24b859f081525c7e0f751f5e7ebb)

```java
try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, data) returns (bytes4 retval) {
    return retval == IERC721Receiver.onERC721Received.selector;
} catch (bytes memory reason)
```

Recommended Mitigation Steps:

-   Implement `safeTransferReturn` so that it checks the required magic bytes: `IERC721Receiver.onERC721Received.selector`.

The `magic bytes`: These come from [ERC165](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-165.md), which gives contracts a way to query each other about what interfaces they support. The return value is the XOR of the [function selectors](https://docs.soliditylang.org/en/v0.4.24/abi-spec.html#function-selector) of the supported functions.

<br>
<hr>

## 3. [M-03] Replay attack in case of hard fork - Cross-Chain Replay Attack (Sometimes Low)

_If there is ever a hardfork for (e.g., 'Golom') then `EIP712_DOMAIN_TYPEHASH` value will become invalid. This is because the chainId parameter is computed in constructor. This means even after hard fork chainId would remain same which is incorrect and could cause possible replay attacks_

_The `constructor` token calculates the `chainId` it should assign during its execution and permanently stores it in an `immutable` variable. Should Ethereum fork in the feature, the `chainId` will change however the one used by the permits will not enabling a user to use any new permits on both chains thus breaking the token on the forked chain permanently._

[Please consult EIP1344 for more details.](https://eips.ethereum.org/EIPS/eip-1344#rationale)

-   Observe the constructor:

```java
constructor(address _governance) {
        // sets governance as owner
        _transferOwnership(_governance);
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        EIP712_DOMAIN_TYPEHASH = keccak256(
            abi.encode(
                keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
                keccak256(bytes('GOLOM.IO')),
                keccak256(bytes('1')),
                chainId,
                address(this)
            )
        );
    }
```

[_Resolved_](https://github.com/golom-protocol/contracts/commit/d8a24442b8f3a764139e312ed393e5d5ffb7e596)

-   As we can see the chainId is derived and then hardcoded in `EIP712_DOMAIN_TYPEHASH`.
-   This means even after hard fork, `EIP712_DOMAIN_TYPEHASH` value will remain same and point to incorrect chainId.

Recommended Mitigation Steps:

-   The `EIP712_DOMAIN_TYPEHASH` variable should be recomputed everytime by placing current value of chainId.
-   The mitigation action that should be applied is the calculation of the `chainId` dynamically on each `permit` invocation. As a gas optimization, the deployment pre-calculated hash for the permits can be stored to an `immutable` variable and a validation can occur on the `permit` function that ensure the current `chainId` is equal to the one of the cached hash and if not, to re-calculate it on the spot.

<br>
<hr>

## 4. `call` opcode’s return value not checked.

_In the low level functions that return ETH to the user after an aggregate trade fails to validate the return value of the ETH transfer. If the transfer fails, the user's ETH would become stuck in the contract._

```java
function _returnETHIfAny() internal {
    assembly {
        if gt(selfbalance(), 0) {
            let status := call(gas(), caller(), selfbalance(), 0, 0, 0, 0)
        }
    }
}
```

Recommended Mitigation Steps:

-   Confirm that the call returns true.
-   Check the return value the call opcode.

```java
function _returnETHIfAny() internal {
    assembly {
        if gt(selfbalance(), 0) {
            let status := call(gas(), caller(), selfbalance(), 0, 0, 0, 0)
        }
    }

+   if (!status) revert ETHTransferFail();
}
```

## 5. Unchecked return value from low-level `call()`

_The return value of the low-level call is not checked, so if the call fails, the Ether will be locked in the contract. If the low level is used to prevent blocking operations, consider logging failed calls._

```ts
address(INTERMEDIATE_TOKEN).call{value: msg.value}("");
```

Recommended Mitigation Steps:

-   Add condition to check return value.

<br>
<hr>

## 6. ERC20 return values not checked.

_The `ERC20.transfer()` and `ERC20.transferFrom()` functions return a boolean value indicating success. This parameter needs to be checked for success. Some tokens do not revert if the transfer failed but return `false` instead._

See:

-   `SingleNativeTokenExitV2.exit`’s `outputToken.transfer(msg.sender, outputTokenBalance);`
-   `PieFactoryContract.bakePie`’s `pie.transfer(msg.sender, _initialSupply);`

Impact:
_Tokens that don’t actually perform the transfer and return `false` are still counted as a correct transfer and the tokens remain in the `SingleNativeTokenExitV2` contract and could potentially be stolen by someone else._

Recommended Mitigation Steps:

-   We recommend using [OpenZeppelin’s](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.1/contracts/token/ERC20/utils/SafeERC20.sol#L74) `SafeERC20` versions with the `safeTransfer` and `safeTransferFrom` functions that handle the return value check as well as non-standard-compliant tokens.

<br>
<hr>

## 7. The `owner` is a single point of failure and a centralization risk.

_Having a single EOA as the only owner of contracts is a large centralization risk and a single point of failure. A single private key may be taken in a hack, or the sole holder of the key may become unable to retrieve the key when necessary. Consider changing to a multi-signature setup, or having a role-based authorization model._

[Example](https://github.com/code-423n4/2023-05-venus/blob/9853f6f4fe906b635e214b22de9f627c6a17ba5b/contracts/Comptroller.sol#L927-L927):

```java
File: contracts/Comptroller.sol

927:     function addRewardsDistributor(RewardsDistributor _rewardsDistributor) external onlyOwner {

961:     function setPriceOracle(PriceOracle newOracle) external onlyOwner {

973:     function setMaxLoopsLimit(uint256 limit) external onlyOwner {
```

<br>
<hr>
<br>

based on real reports [Code4arena](https://code4rena.com/reports)
