// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.7;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IAccessControlManager } from "./interfaces/IAccessControlManager.sol";
import { Errors } from "./utils/Errors.sol";

/// @title WavePointToken
/// @notice Non-transferable token for 1Wave points system within Merkl
/// @dev Based on Merkl's PointToken reference contract
contract WavePointToken is ERC20 {
    mapping(address => bool) public minters;
    mapping(address => bool) public whitelistedRecipients;
    IAccessControlManager public accessControlManager;
    uint8 public allowedTransfers;
    
    // Tracking for future token claim
    mapping(address => uint256) public burnedAmount; // Total amount burned by user
    bool public burnForClaimEnabled; // Whether users can burn their tokens for future claim
    
    event BurnedForClaim(address indexed user, uint256 amount, uint256 totalBurned);

    constructor(
        string memory name_,
        string memory symbol_,
        address _minter,
        address _accessControlManager
    ) ERC20(name_, symbol_) {
        if (_accessControlManager == address(0) || _minter == address(0)) revert Errors.ZeroAddress();
        accessControlManager = IAccessControlManager(_accessControlManager);
        minters[_minter] = true;
    }

    modifier onlyGovernorOrGuardian() {
        if (!accessControlManager.isGovernorOrGuardian(msg.sender)) revert Errors.NotGovernorOrGuardian();
        _;
    }

    modifier onlyGovernor() {
        if (!accessControlManager.isGovernor(msg.sender)) revert Errors.NotGovernor();
        _;
    }

    modifier onlyMinter() {
        if (!minters[msg.sender]) revert Errors.NotTrusted();
        _;
    }

    function mint(address account, uint256 amount) external onlyMinter {
        _mint(account, amount);
    }

    function burn(address account, uint256 amount) external onlyMinter {
        _burn(account, amount);
    }

    function mintBatch(address[] memory accounts, uint256[] memory amounts) external onlyMinter {
        uint256 length = accounts.length;
        for (uint256 i = 0; i < length; ++i) {
            _mint(accounts[i], amounts[i]);
        }
    }

    function toggleMinter(address minter) external onlyGovernor {
        minters[minter] = !minters[minter];
    }

    function toggleAllowedTransfers() external onlyGovernorOrGuardian {
        allowedTransfers = 1 - allowedTransfers;
    }

    function toggleWhitelistedRecipient(address recipient) external onlyGovernorOrGuardian {
        whitelistedRecipients[recipient] = !whitelistedRecipients[recipient];
    }

    /// @notice Enable or disable burn for claim functionality
    /// @param enabled Whether to enable burn for claim
    function setBurnForClaimEnabled(bool enabled) external onlyGovernorOrGuardian {
        burnForClaimEnabled = enabled;
    }

    /// @notice Burn user's own tokens for future claim
    /// @param amount Amount of tokens to burn
    function burnForClaim(uint256 amount) external {
        if (!burnForClaimEnabled) revert Errors.NotAllowed();
        if (amount == 0) revert Errors.ZeroAmount();
        
        address user = msg.sender;
        if (balanceOf(user) < amount) revert Errors.InsufficientBalance();
        
        _burn(user, amount);
        burnedAmount[user] += amount;
        
        emit BurnedForClaim(user, amount, burnedAmount[user]);
    }

    /// @notice Get total amount burned by a user (for future claim tracking)
    /// @param user Address to check
    /// @return Total amount burned by the user
    function getBurnedAmount(address user) external view returns (uint256) {
        return burnedAmount[user];
    }

    function _beforeTokenTransfer(address from, address to, uint256) internal view {
        if (allowedTransfers == 0 && from != address(0) && to != address(0) && !whitelistedRecipients[from] && !whitelistedRecipients[to])
            revert Errors.NotAllowed();
    }
}
