// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

/// Test-only ERC-1271 wallet: valid iff the owner EOA (storage slot 0) signed the hash.
/// Placed on anvil with anvil_setCode + anvil_setStorageAt (runtime bytecode in mock-wallet.ts).
contract MockWallet {
    address owner;

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        if (sig.length != 65) return 0xffffffff;
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        address signer = ecrecover(hash, v, r, s);
        return signer != address(0) && signer == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}
