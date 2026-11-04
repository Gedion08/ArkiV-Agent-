// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title RecorderAnchor — anchors AFR checkpoint roots. Immutable, holds no funds.
/// @dev L5 §2 [NORMATIVE interface]. Roots are OZ StandardMerkleTree roots over
///      (bytes32 agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot), L1 §6.
contract RecorderAnchor {
    address public immutable admin; // Safe multisig; can only manage the recorder allowlist
    mapping(address => bool) public isRecorder;
    uint64 public epoch; // increments per anchor
    mapping(uint64 => bytes32) public rootOf; // epoch → root
    mapping(bytes32 => uint64) public epochOf; // root → epoch (0 = unknown; epochs start at 1)

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

    error NotAdmin();
    error NotRecorder();
    error ZeroRoot();
    error DuplicateRoot();
    error EmptyAnchor();

    constructor(address admin_, address[] memory recorders) {
        admin = admin_;
        for (uint256 i; i < recorders.length; ++i) {
            isRecorder[recorders[i]] = true;
            emit RecorderSet(recorders[i], true);
        }
    }

    modifier onlyRecorder() {
        if (!isRecorder[msg.sender]) revert NotRecorder();
        _;
    }

    function setRecorder(address r, bool allowed) external {
        if (msg.sender != admin) revert NotAdmin();
        isRecorder[r] = allowed;
        emit RecorderSet(r, allowed);
    }

    /// Rollup anchor: root of StandardMerkleTree over (bytes32 agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot)
    function anchorRoot(bytes32 root, uint32 leafCount, bytes32 manifestKey)
        external
        onlyRecorder
        returns (uint64 e)
    {
        if (root == bytes32(0)) revert ZeroRoot();
        if (leafCount == 0) revert EmptyAnchor();
        if (epochOf[root] != 0) revert DuplicateRoot();
        e = ++epoch;
        rootOf[e] = root;
        epochOf[root] = e;
        emit Anchored(e, root, leafCount, manifestKey, msg.sender);
    }

    /// Single-agent anchor (self-host / dedicated). Root = leaf hash (single-leaf StandardMerkleTree).
    function anchor(bytes32 agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot)
        external
        onlyRecorder
        returns (uint64 e)
    {
        bytes32 leaf = leafHash(agentKey, lane, seqTo, chainRoot);
        if (epochOf[leaf] != 0) revert DuplicateRoot();
        e = ++epoch;
        rootOf[e] = leaf;
        epochOf[leaf] = e;
        emit Anchored(e, leaf, 1, bytes32(0), msg.sender);
        emit AgentAnchored(e, agentKey, lane, seqTo, chainRoot);
    }

    function leafHash(bytes32 agentKey, uint32 lane, uint64 seqTo, bytes32 chainRoot)
        public
        pure
        returns (bytes32)
    {
        return keccak256(bytes.concat(keccak256(abi.encode(agentKey, lane, seqTo, chainRoot))));
    }

    function verify(
        uint64 e,
        bytes32 agentKey,
        uint32 lane,
        uint64 seqTo,
        bytes32 chainRoot,
        bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 root = rootOf[e];
        return root != bytes32(0)
            && MerkleProof.verifyCalldata(proof, root, leafHash(agentKey, lane, seqTo, chainRoot));
    }
}
