// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.7;

/// @title Errors
/// @notice Custom errors for WaveToken
library Errors {
    error ZeroAddress();
    error NotGovernorOrGuardian();
    error NotGovernor();
    error NotTrusted();
    error NotAllowed();
    error InsufficientBalance();
    error ZeroAmount();
}
