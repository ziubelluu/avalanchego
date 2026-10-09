//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Chameleon Hash Interface
/// @notice A precompile that checks an opening of the chameleon hash (points
/// of G1 on BLS12-381), so normal contracts can do it on-chain since Solidity
/// can't.
interface IChameleonHash {
    /// @notice Check that (m, r) opens digest under the public key hk.
    /// @param hk the 48-byte public key y.
    /// @param m the message.
    /// @param r the randomness, the 128-byte proof (e1, e2, s1, s2).
    /// @param digest the 96-byte digest (c1, c2).
    /// @return ok true if the opening verifies.
    function verify(bytes calldata hk, bytes calldata m, bytes calldata r, bytes calldata digest)
        external
        view
        returns (bool ok);
}
