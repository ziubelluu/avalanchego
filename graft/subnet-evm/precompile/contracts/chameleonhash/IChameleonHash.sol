//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Chameleon Hash Interface
/// @notice A precompile that computes the chameleon hash (2048-bit numbers
/// mod p), so normal contracts can do it on-chain since Solidity can't.
interface IChameleonHash {
    /// @notice Compute h = r - (y^H(m||r) * g^s mod p) mod q.
    /// @param hk the 256-byte public key y.
    /// @param m the message.
    /// @param r the randomness, r and s together (512 bytes).
    /// @return digest the 256-byte digest.
    function hash(bytes calldata hk, bytes calldata m, bytes calldata r)
        external
        view
        returns (bytes memory digest);
}
