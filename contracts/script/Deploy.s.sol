// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {RecorderAnchor} from "../src/RecorderAnchor.sol";

/// L5 §2 deployment: CREATE2 through the canonical deterministic deployer with a fixed salt, so the
/// same (admin, recorders) gives the same address on every chain. Idempotent: if the contract is
/// already there, nothing is sent.
///
///   forge script script/Deploy.s.sol --rpc-url base_sepolia --broadcast --verify
///
/// Env: AFR_DEPLOYER_KEY (pays gas, gets no role), AFR_ANCHOR_ADMIN (Safe; edits the allowlist only),
/// AFR_ANCHOR_RECORDERS (comma-separated anchor service signers).
contract Deploy is Script {
    bytes32 public constant SALT = keccak256("afr/RecorderAnchor/v1");

    function run() external returns (RecorderAnchor a) {
        address admin = vm.envAddress("AFR_ANCHOR_ADMIN");
        address[] memory recorders = vm.envAddress("AFR_ANCHOR_RECORDERS", ",");
        vm.startBroadcast(vm.envUint("AFR_DEPLOYER_KEY"));
        a = deploy(admin, recorders);
        vm.stopBroadcast();
    }

    function predict(address admin, address[] memory recorders) public pure returns (address) {
        return
            vm.computeCreate2Address(SALT, keccak256(initCode(admin, recorders)), CREATE2_FACTORY);
    }

    function deploy(address admin, address[] memory recorders) public returns (RecorderAnchor) {
        require(admin != address(0), "AFR_ANCHOR_ADMIN is zero");
        require(recorders.length > 0, "AFR_ANCHOR_RECORDERS is empty");
        require(CREATE2_FACTORY.code.length > 0, "no CREATE2 deployer on this chain");
        address at = predict(admin, recorders);
        if (at.code.length == 0) {
            (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(SALT, initCode(admin, recorders)));
            require(ok && at.code.length > 0, "CREATE2 deploy failed");
            console.log("RecorderAnchor deployed at", at);
        } else {
            console.log("RecorderAnchor already deployed at", at);
        }
        return RecorderAnchor(at);
    }

    function initCode(address admin, address[] memory recorders)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(type(RecorderAnchor).creationCode, abi.encode(admin, recorders));
    }
}
