// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {RecorderAnchor} from "../src/RecorderAnchor.sol";
import {Deploy} from "../script/Deploy.s.sol";

contract DeployTest is Test {
    Deploy internal d = new Deploy();
    address internal admin = makeAddr("admin");
    address[] internal recorders;

    function setUp() public {
        recorders.push(makeAddr("recorder"));
    }

    function test_deploysAtPredictedAddressOnce() public {
        address at = d.predict(admin, recorders);
        assertEq(at.code.length, 0);
        RecorderAnchor a = d.deploy(admin, recorders);
        assertEq(address(a), at);
        assertEq(a.admin(), admin);
        assertTrue(a.isRecorder(recorders[0]));
        // a re-run finds it and sends nothing
        uint64 nonceBefore = vm.getNonce(address(d));
        assertEq(address(d.deploy(admin, recorders)), at);
        assertEq(vm.getNonce(address(d)), nonceBefore);
    }

    function test_addressDependsOnRolesOnly() public {
        address[] memory other = new address[](1);
        other[0] = makeAddr("other");
        assertTrue(d.predict(admin, recorders) != d.predict(admin, other));
        assertTrue(d.predict(admin, recorders) != d.predict(makeAddr("admin2"), recorders));
        assertEq(d.predict(admin, recorders), new Deploy().predict(admin, recorders));
    }

    function test_rejectsMissingRoles() public {
        vm.expectRevert("AFR_ANCHOR_ADMIN is zero");
        d.deploy(address(0), recorders);
        vm.expectRevert("AFR_ANCHOR_RECORDERS is empty");
        d.deploy(admin, new address[](0));
    }
}
