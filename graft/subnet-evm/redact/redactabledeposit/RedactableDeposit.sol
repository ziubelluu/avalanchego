//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev The chameleon-hash precompile (does the crypto Solidity can't do).
interface IChameleonHash {
    function hash(bytes calldata hk, bytes calldata m, bytes calldata r)
        external
        view
        returns (bytes memory digest);
}

/// @title RedactableDeposit
/// @notice A normal contract that keeps only the chameleon digest in state.
/// The opening (blob, randomness) goes in calldata and is never stored, so it
/// can be redacted later. `store` checks on-chain that CH(blob, r) == digest by
/// calling the chameleon-hash precompile. Anyone can deploy one.
contract RedactableDeposit {
    /// @dev The chameleon-hash precompile address.
    address private constant CHAMELEON = 0x0300000000000000000000000000000000000000;

    /// @dev id => digest. Slot 0.
    mapping(bytes32 => bytes) private digests;

    /// @notice The authority public key. Slot 1.
    bytes public authorityKey;

    /// @notice Emitted on each deposit (only id + digest, so the opening isn't logged).
    event Deposited(bytes32 indexed id, bytes digest);

    constructor(bytes memory hk) {
        authorityKey = hk;
    }

    /// @notice Save `digest` for `id` after checking CH(blob, randomness) == digest.
    /// blob and randomness are only in calldata, not stored.
    function store(
        bytes32 id,
        bytes calldata blob,
        bytes calldata randomness,
        bytes calldata digest
    ) external {
        require(digests[id].length == 0, "id already used");

        bytes memory recomputed = IChameleonHash(CHAMELEON).hash(authorityKey, blob, randomness);
        require(keccak256(recomputed) == keccak256(digest), "opening does not commit to digest");

        digests[id] = digest;
        emit Deposited(id, digest);
    }

    /// @notice Read back the digest committed for `id` (empty if unset).
    function digestOf(bytes32 id) external view returns (bytes memory) {
        return digests[id];
    }
}
