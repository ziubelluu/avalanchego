//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Chameleon Hash Interface
/// @notice A precompile that computes the chameleon hash (on BLS12-381 G1), so
/// normal contracts can do it on-chain since Solidity can't. Like bn256/BLS.
interface IChameleonHash {
    /// @notice Compute CH(m, r) = g^H(m) * y^r.
    /// @param hk the 48-byte public key y.
    /// @param m the message.
    /// @param r the randomness.
    /// @return digest the 48-byte digest.
    function hash(bytes calldata hk, bytes calldata m, bytes calldata r)
        external
        view
        returns (bytes memory digest);
}
