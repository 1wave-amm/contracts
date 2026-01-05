// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.7;

/// @title IAccessControlManager
/// @notice Interface for access control management
interface IAccessControlManager {
    /// @notice Check if address is governor or guardian
    /// @param account Address to check
    /// @return true if account is governor or guardian
    function isGovernorOrGuardian(address account) external view returns (bool);

    /// @notice Check if address is governor
    /// @param account Address to check
    /// @return true if account is governor
    function isGovernor(address account) external view returns (bool);
}
