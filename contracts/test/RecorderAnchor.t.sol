// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {RecorderAnchor} from "../src/RecorderAnchor.sol";

/// L5 §2 Foundry suite (A1): unit, TS vector parity (anchor.json), fuzz, invariants, gas.
contract RecorderAnchorTest is Test {
    event RecorderSet(address indexed recorder, bool allowed);
    event Anchored(
        uint64 indexed epoch,
        bytes32 indexed root,
        uint32 leafCount,
        bytes32 manifestKey,
        address indexed recorder
    );
    event AgentAnchored(
        uint64 indexed epoch, bytes32 indexed agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot
    );

    address internal admin = makeAddr("admin");
    address internal rec = makeAddr("recorder");
    RecorderAnchor internal a;

    function setUp() public {
        address[] memory rs = new address[](1);
        rs[0] = rec;
        a = new RecorderAnchor(admin, rs);
    }

    // ---- unit ----

    function test_constructorSetsAdminAndRecorders() public {
        address[] memory rs = new address[](2);
        rs[0] = address(0xA1);
        rs[1] = address(0xA2);
        vm.expectEmit(true, false, false, true);
        emit RecorderSet(rs[0], true);
        vm.expectEmit(true, false, false, true);
        emit RecorderSet(rs[1], true);
        RecorderAnchor b = new RecorderAnchor(admin, rs);
        assertEq(b.admin(), admin);
        assertTrue(b.isRecorder(rs[0]) && b.isRecorder(rs[1]));
        assertFalse(b.isRecorder(admin));
        assertEq(b.epoch(), 0);
    }

    function test_setRecorderOnlyAdmin() public {
        address r = address(0xBEEF);
        vm.expectRevert(RecorderAnchor.NotAdmin.selector);
        vm.prank(rec);
        a.setRecorder(r, true);

        vm.expectEmit(true, false, false, true);
        emit RecorderSet(r, true);
        vm.prank(admin);
        a.setRecorder(r, true);
        assertTrue(a.isRecorder(r));

        vm.prank(admin);
        a.setRecorder(rec, false);
        vm.expectRevert(RecorderAnchor.NotRecorder.selector);
        vm.prank(rec);
        a.anchorRoot(keccak256("x"), 1, 0);
    }

    function test_onlyRecordersAnchor() public {
        vm.startPrank(admin); // the admin manages the allowlist, it can't anchor
        vm.expectRevert(RecorderAnchor.NotRecorder.selector);
        a.anchorRoot(keccak256("x"), 1, 0);
        vm.expectRevert(RecorderAnchor.NotRecorder.selector);
        a.anchor(keccak256("ak"), 0, 1, keccak256("cr"));
        vm.stopPrank();
    }

    function test_anchorRootRevertsAndEvents() public {
        vm.startPrank(rec);
        vm.expectRevert(RecorderAnchor.ZeroRoot.selector);
        a.anchorRoot(bytes32(0), 1, 0);
        vm.expectRevert(RecorderAnchor.EmptyAnchor.selector);
        a.anchorRoot(keccak256("r1"), 0, 0);

        bytes32 r1 = keccak256("r1");
        bytes32 mk = keccak256("manifest");
        vm.expectEmit(true, true, true, true);
        emit Anchored(1, r1, 3, mk, rec);
        assertEq(a.anchorRoot(r1, 3, mk), 1);
        assertEq(a.epoch(), 1);
        assertEq(a.rootOf(1), r1);
        assertEq(a.epochOf(r1), 1);

        vm.expectRevert(RecorderAnchor.DuplicateRoot.selector);
        a.anchorRoot(r1, 3, mk);
        assertEq(a.anchorRoot(keccak256("r2"), 1, 0), 2);
        assertEq(a.epoch(), 2);
        vm.stopPrank();
    }

    function test_singleAnchorEventsAndDuplicates() public {
        bytes32 ak = keccak256("ak");
        bytes32 cr = keccak256("cr");
        bytes32 leaf = a.leafHash(ak, 7, 42, cr);
        vm.startPrank(rec);
        vm.expectEmit(true, true, true, true);
        emit Anchored(1, leaf, 1, bytes32(0), rec);
        vm.expectEmit(true, true, false, true);
        emit AgentAnchored(1, ak, 7, 42, cr);
        assertEq(a.anchor(ak, 7, 42, cr), 1);
        assertEq(a.rootOf(1), leaf);
        assertTrue(a.verify(1, ak, 7, 42, cr, new bytes32[](0)));

        vm.expectRevert(RecorderAnchor.DuplicateRoot.selector);
        a.anchor(ak, 7, 42, cr);
        // a rollup can't reuse a single anchor's root either
        vm.expectRevert(RecorderAnchor.DuplicateRoot.selector);
        a.anchorRoot(leaf, 1, 0);
        vm.stopPrank();
    }

    function test_verifyUnknownEpochIsFalse() public view {
        assertFalse(a.verify(0, bytes32(0), 0, 0, bytes32(0), new bytes32[](0)));
        assertFalse(a.verify(5, keccak256("ak"), 0, 1, keccak256("cr"), new bytes32[](0)));
    }

    function test_holdsNoFunds() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(a).call{value: 1}("");
        assertFalse(ok);
        assertEq(address(a).balance, 0);
    }

    /// L5 §2 target: < 60k execution gas in steady state (the first anchor ever also pays the epoch
    /// slot's 0 → 1 write). forge runs with isolate = true, so `used` includes the 21k intrinsic cost.
    function test_gas_anchorRoot() public {
        vm.startPrank(rec);
        a.anchorRoot(keccak256("first"), 1, 0);
        uint256 g = gasleft();
        a.anchorRoot(keccak256("gas"), 100, keccak256("manifest"));
        uint256 used = g - gasleft();
        vm.stopPrank();
        emit log_named_uint("anchorRoot tx gas (steady state)", used);
        assertLt(used - 21_000, 60_000);
    }

    // ---- vector parity with packages/test-vectors (L1 §6) ----

    function test_vectors_anchorJson() public {
        string memory json = vm.readFile(
            string.concat(vm.projectRoot(), "/../packages/test-vectors/vectors/anchor.json")
        );
        assertEq(vm.parseJsonString(json, ".format"), "afr/anchor");
        uint256 cases;
        for (uint256 c; vm.keyExistsJson(json, _at(".cases", c)); ++c) {
            string memory k = _at(".cases", c);
            bytes32 root = vm.parseJsonBytes32(json, string.concat(k, ".expected.root"));
            vm.prank(rec);
            uint64 e = a.anchorRoot(root, 1, 0);
            uint256 n;
            for (; vm.keyExistsJson(json, _at(string.concat(k, ".expected.sorted"), n)); ++n) {
                string memory l = _at(string.concat(k, ".expected.sorted"), n);
                bytes32 ak = vm.parseJsonBytes32(json, string.concat(l, ".agent_key"));
                uint32 lane = uint32(vm.parseJsonUint(json, string.concat(l, ".lane")));
                uint64 seqTo = uint64(vm.parseJsonUint(json, string.concat(l, ".seq_to")));
                bytes32 cr = vm.parseJsonBytes32(json, string.concat(l, ".chain_root"));
                bytes32[] memory proof = _proof(json, _at(string.concat(k, ".expected.proofs"), n));
                assertTrue(a.verify(e, ak, lane, seqTo, cr, proof), "vector proof");
                assertFalse(a.verify(e, ak, lane, seqTo ^ 1, cr, proof), "forged seq_to");
                if (proof.length == 0) assertEq(a.leafHash(ak, lane, seqTo, cr), root);
            }
            assertGt(n, 0);
            ++cases;
        }
        assertGe(cases, 2);
    }

    function _at(string memory k, uint256 i) internal pure returns (string memory) {
        return string.concat(k, "[", vm.toString(i), "]");
    }

    /// Empty JSON arrays have no element type to decode, so a missing first element means [].
    function _proof(string memory json, string memory k) internal view returns (bytes32[] memory) {
        if (!vm.keyExistsJson(json, string.concat(k, "[0]"))) return new bytes32[](0);
        return vm.parseJsonBytes32Array(json, k);
    }

    // ---- fuzz: random leaves → tree built here → on-chain verify ----

    function testFuzz_randomTreesVerify(bytes32 seed, uint8 size, uint8 pick) public {
        uint256 n = bound(size, 1, 33);
        bytes32[] memory leaves = new bytes32[](n);
        bytes32[4][] memory vals = new bytes32[4][](n);
        for (uint256 i; i < n; ++i) {
            bytes32 r = keccak256(abi.encode(seed, i));
            vals[i] = [
                r,
                bytes32(uint256(uint32(uint256(r) >> 32))),
                bytes32(uint256(uint64(uint256(r)))),
                keccak256(abi.encode(r))
            ];
            leaves[i] = a.leafHash(
                vals[i][0], uint32(uint256(vals[i][1])), uint64(uint256(vals[i][2])), vals[i][3]
            );
        }
        uint256 j = bound(pick, 0, n - 1);
        (bytes32 root, bytes32[] memory proof) = _rootAndProof(leaves, j);
        vm.prank(rec);
        uint64 e = a.anchorRoot(root, uint32(n), 0);
        bytes32 ak = vals[j][0];
        uint32 lane = uint32(uint256(vals[j][1]));
        uint64 seqTo = uint64(uint256(vals[j][2]));
        bytes32 cr = vals[j][3];
        assertTrue(a.verify(e, ak, lane, seqTo, cr, proof));
        assertFalse(a.verify(e, ak, lane ^ 1, seqTo, cr, proof));
        assertFalse(a.verify(e, ak, lane, seqTo ^ 1, cr, proof));
        assertFalse(a.verify(e, ak, lane, seqTo, ~cr, proof));
        assertFalse(a.verify(e + 1, ak, lane, seqTo, cr, proof));
    }

    /// Commutative-keccak Merkle tree (the OZ MerkleProof convention); an odd node is carried up.
    function _rootAndProof(bytes32[] memory level, uint256 idx)
        internal
        pure
        returns (bytes32 root, bytes32[] memory proof)
    {
        bytes32[] memory p = new bytes32[](8);
        uint256 depth;
        while (level.length > 1) {
            bytes32[] memory next = new bytes32[]((level.length + 1) / 2);
            for (uint256 i; i < level.length; i += 2) {
                next[i / 2] = i + 1 < level.length ? _pair(level[i], level[i + 1]) : level[i];
            }
            uint256 sib = idx ^ 1;
            if (sib < level.length) p[depth++] = level[sib];
            idx /= 2;
            level = next;
        }
        root = level[0];
        proof = new bytes32[](depth);
        for (uint256 i; i < depth; ++i) {
            proof[i] = p[i];
        }
    }

    function _pair(bytes32 x, bytes32 y) internal pure returns (bytes32) {
        return x < y ? keccak256(abi.encode(x, y)) : keccak256(abi.encode(y, x));
    }
}

/// Drives random anchors for the invariant suite and remembers every root that landed.
contract AnchorHandler is Test {
    RecorderAnchor internal immutable a;
    address internal immutable rec;
    uint256 public successes;
    bytes32[] public roots;

    constructor(RecorderAnchor a_, address rec_) {
        a = a_;
        rec = rec_;
    }

    function anchorRoot(bytes32 root, uint32 leafCount) external {
        vm.prank(rec);
        try a.anchorRoot(root, leafCount, 0) {
            ++successes;
            roots.push(root);
        } catch {}
    }

    function anchor(bytes32 ak, uint32 lane, uint64 seqTo, bytes32 cr) external {
        vm.prank(rec);
        try a.anchor(ak, lane, seqTo, cr) {
            ++successes;
            roots.push(a.leafHash(ak, lane, seqTo, cr));
        } catch {}
    }

    /// Replays a landed root: must always revert DuplicateRoot.
    function replay(uint256 i) external {
        if (roots.length == 0) return;
        vm.prank(rec);
        bytes32 r = roots[i % roots.length];
        try a.anchorRoot(r, 1, 0) {
            ++successes;
            roots.push(r); // a second epoch for r fails invariant_rootOfEpochOfRoundTrips
        } catch {}
    }

    function rootCount() external view returns (uint256) {
        return roots.length;
    }
}

contract RecorderAnchorInvariantTest is Test {
    RecorderAnchor internal a;
    AnchorHandler internal h;

    function setUp() public {
        address rec = makeAddr("recorder");
        address[] memory rs = new address[](1);
        rs[0] = rec;
        a = new RecorderAnchor(makeAddr("admin"), rs);
        h = new AnchorHandler(a, rec);
        targetContract(address(h));
    }

    function invariant_epochCountsSuccessfulAnchors() public view {
        assertEq(a.epoch(), h.successes());
    }

    function invariant_rootOfEpochOfRoundTrips() public view {
        uint256 n = h.rootCount();
        for (uint256 i; i < n; ++i) {
            bytes32 r = h.roots(i);
            assertEq(a.rootOf(a.epochOf(r)), r);
            assertEq(a.epochOf(r), i + 1);
        }
    }
}
