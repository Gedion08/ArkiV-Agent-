// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// P0 smoke test: proves forge-std and OZ 5.x remappings resolve. RecorderAnchor arrives in P3.
contract SmokeTest is Test {
    function test_ozResolves() public pure {
        bytes32 h = MessageHashUtils.toEthSignedMessageHash(bytes32(0));
        assertTrue(h != bytes32(0));
    }
}
