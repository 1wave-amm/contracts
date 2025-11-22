// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {BaseAdapter} from "@factordao/contracts/BaseAdapter.sol";
import {IAggregator} from "@factordao/contracts/interfaces/IAggregator.sol";
import {AquaAdapterStorage} from "./AquaAdapterStorage.sol";
import {StudioProV1Storage} from "@factordao/contracts/studio/prov1/StudioProV1Storage.sol";

/// @title AquaInterface
interface IAqua {
    // Liquidity Lifecycle Management
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // Ship new strategy with initial balances (immutable after creation)
    function ship(address app, bytes calldata strategy, address[] calldata tokens, uint256[] calldata amounts)
        external
        returns (bytes32 strategyHash);

    // Deactivate strategy and withdraw all balances
    function dock(address app, bytes32 strategyHash, address[] calldata tokens) external;

    // Swap Execution Only
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // Pull tokens from maker during swap (called by apps)
    function pull(address maker, bytes32 strategyHash, address token, uint256 amount, address to) external;

    // Push tokens to maker's strategy balance during swap
    function push(address maker, address app, bytes32 strategyHash, address token, uint256 amount) external;

    // Queries
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // Query virtual balance
    function rawBalances(address maker, address app, bytes32 strategyHash, address token)
        external
        view
        returns (uint248 balance, uint8 tokensCount);

    // Query multiple token balances with active strategy validation
    // Reverts if any token is not part of the active strategy
    function safeBalances(address maker, address app, bytes32 strategyHash, address token0, address token1)
        external
        view
        returns (uint256 balance0, uint256 balance1);
}

/// @title AquaAdapter
/// @notice Adapter for interacting with Aqua protocol
/// @dev Handles token swaps through Aqua Router
contract AquaAdapter is BaseAdapter {
    error PAIR_ALREADY_EXISTS();
    error INVALID_PRICE();
    error INVALID_INPUT_AMOUNTS();
    error INSUFFICIENT_LIQUIDITY();
    error SWAP_APP_NOT_SET();

    event StrategyShipped(bytes32 pairHash, bytes32 strategyHash);
    event PairSet(address token0, address token1, uint256 feeBps, bytes32 pairHash);

    struct AquaStrategy {
        address maker;
        address token0;
        address token1;
        uint256 feeBps;
        bytes32 salt;
    }

    bytes4 public constant label = bytes4(keccak256("AQUA"));

    // Function selectors for view functions
    bytes4 public constant GET_STRATEGY_DATA_SIG = bytes4(keccak256("getStrategyData(bytes32,address)"));
    bytes4 public constant STRATEGIES_SIG = bytes4(keccak256("strategies(bytes32,address)"));
    bytes4 public constant STRATEGY_NONCES_SIG = bytes4(keccak256("strategyNonces(bytes32)"));
    bytes4 public constant PAIR_EXISTS_SIG = bytes4(keccak256("pairExists(bytes32)"));
    bytes4 public constant PAIRS_LENGTH_SIG = bytes4(keccak256("pairsLength()"));
    bytes4 public constant PAIRS_SIG = bytes4(keccak256("pairs(uint256)"));
    bytes4 public constant CHAINLINK_FEEDS_SIG = bytes4(keccak256("chainlinkFeeds(address)"));
    bytes4 public constant ESTIMATE_OUTPUT_SIG = bytes4(keccak256("estimateOutput(address,address,uint256,uint256)"));
    bytes4 public constant PUBLISH_PAIRS_SIG = bytes4(keccak256("publishPairs()"));

    address immutable addressThis;

    /// @notice Get pairs array length
    function pairsLength() external view returns (uint256) {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        return $.pairs.length;
    }

    /// @notice Get pair by index
    function pairs(uint256 index) external view returns (address token0, address token1, uint256 feeBps) {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        require(index < $.pairs.length, "Index out of bounds");
        AquaAdapterStorage.Pair storage pair = $.pairs[index];
        return (pair.token0, pair.token1, pair.feeBps);
    }

    /// @notice Get strategy data for a pair and DEX
    /// @param pairHash The hash of the pair
    /// @param dex The address of the DEX
    /// @return strategyData The strategy data struct
    function getStrategyData(bytes32 pairHash, address dex) external view returns (AquaAdapterStorage.StrategyData memory) {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        return $.strategies[pairHash][dex];
    }

    /// @notice Get strategy data (public mapping getter)
    function strategies(bytes32 pairHash, address dex) external view returns (AquaAdapterStorage.StrategyData memory) {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        return $.strategies[pairHash][dex];
    }

    /// @notice Get strategy nonce (public mapping getter)
    function strategyNonces(bytes32 pairHash) external view returns (uint256) {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        return $.strategyNonces[pairHash];
    }

    /// @notice Check if pair exists (public mapping getter)
    function pairExists(bytes32 pairHash) external view returns (bool) {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        return $.pairExists[pairHash];
    }

    /// @notice Get chainlink feed (public mapping getter)
    function chainlinkFeeds(address token) external view returns (address) {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        return $.chainlinkFeeds[token];
    }

    /// @notice Get pair hash
    /// @param token0 The address of the first token
    /// @param token1 The address of the second token
    /// @return pairHash The hash of the pair (keccak256(abi.encode(token0, token1)))
    function getPairHash(address token0, address token1) public pure returns (bytes32) {
        return keccak256(abi.encode(token0, token1));
    }

    /// @notice Estimate the output amount for a swap based on strategy balances
    /// @param token0 The address of the first token in the pair
    /// @param token1 The address of the second token in the pair
    /// @param amount0 The amount of token0 to swap (must be 0 if amount1 > 0)
    /// @param amount1 The amount of token1 to swap (must be 0 if amount0 > 0)
    /// @return outputAmount The estimated output amount in the other token
    /// @dev Reverts if both amounts are non-zero or both are zero
    /// @dev Reverts if there's insufficient liquidity
    /// @dev Uses the first DEX for the pair to calculate the output
    /// @dev Uses the price ratio from strategy balances: output = (input * reserveOut) / reserveIn
    function estimateOutput(address token0, address token1, uint256 amount0, uint256 amount1)
        external
        view
        returns (uint256 outputAmount)
    {
        // Validate input: exactly one amount must be non-zero
        if ((amount0 == 0 && amount1 == 0) || (amount0 > 0 && amount1 > 0)) {
            revert INVALID_INPUT_AMOUNTS();
        }

        bytes32 pairHash = keccak256(abi.encode(token0, token1));
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();

        // Find the pair to get its first DEX
        address dex;
        {
            uint256 pairLength = $.pairs.length;
            bool pairFound = false;
            for (uint256 i = 0; i < pairLength; i++) {
                bytes32 currentPairHash = keccak256(abi.encode($.pairs[i].token0, $.pairs[i].token1));
                if (currentPairHash == pairHash) {
                    if ($.pairs[i].dexes.length == 0) {
                        revert INSUFFICIENT_LIQUIDITY();
                    }
                    dex = $.pairs[i].dexes[0];
                    pairFound = true;
                    break;
                }
            }
            if (!pairFound || dex == address(0)) {
                revert INSUFFICIENT_LIQUIDITY();
            }
        }

        AquaAdapterStorage.StrategyData memory strategy = $.strategies[pairHash][dex];
        if (strategy.strategyHash == bytes32(0)) {
            revert INSUFFICIENT_LIQUIDITY();
        }

        // Get actual balances from the Aqua strategy vault for the first DEX
        (uint256 reserve0, uint256 reserve1) =
            aqua.safeBalances(address(this), dex, strategy.strategyHash, token0, token1);

        if (reserve0 == 0 || reserve1 == 0) {
            revert INSUFFICIENT_LIQUIDITY();
        }

        if (amount0 > 0) {
            // Swapping token0 for token1: output1 = (amount0 * reserve1) / reserve0
            outputAmount = (amount0 * reserve1) / reserve0;
            if (outputAmount > reserve1) revert INSUFFICIENT_LIQUIDITY();
        } else {
            // Swapping token1 for token0: output0 = (amount1 * reserve0) / reserve1
            outputAmount = (amount1 * reserve0) / reserve1;
            if (outputAmount > reserve0) revert INSUFFICIENT_LIQUIDITY();
        }

        return outputAmount;
    }

    IAqua public immutable aqua = IAqua(0x499943E74FB0cE105688beeE8Ef2ABec5D936d31);

    /// @notice Constructor for AquaAdapter
    /// @param isProAdapter Boolean indicating if this is a pro adapter
    constructor(bool isProAdapter) BaseAdapter(isProAdapter) {
        addressThis = address(this);
    }

    /// @notice Internal function to activate view function selectors in the vault
    /// @dev Registers view function selectors and publishPairs so they can be called on the vault
    function _activateViewFunctions() internal {
        StudioProV1Storage.StudioProV1DS storage $_sb = StudioProV1Storage.s();
        $_sb.funcSelectors[GET_STRATEGY_DATA_SIG] = StudioProV1Storage.SelectorAdapter({ isActive: true, adapter: addressThis });
        $_sb.funcSelectors[STRATEGIES_SIG] = StudioProV1Storage.SelectorAdapter({ isActive: true, adapter: addressThis });
        $_sb.funcSelectors[STRATEGY_NONCES_SIG] = StudioProV1Storage.SelectorAdapter({ isActive: true, adapter: addressThis });
        $_sb.funcSelectors[PAIR_EXISTS_SIG] = StudioProV1Storage.SelectorAdapter({ isActive: true, adapter: addressThis });
        $_sb.funcSelectors[PAIRS_LENGTH_SIG] = StudioProV1Storage.SelectorAdapter({ isActive: true, adapter: addressThis });
        $_sb.funcSelectors[PAIRS_SIG] = StudioProV1Storage.SelectorAdapter({ isActive: true, adapter: addressThis });
        $_sb.funcSelectors[CHAINLINK_FEEDS_SIG] = StudioProV1Storage.SelectorAdapter({ isActive: true, adapter: addressThis });
        $_sb.funcSelectors[ESTIMATE_OUTPUT_SIG] = StudioProV1Storage.SelectorAdapter({ isActive: true, adapter: addressThis });
        $_sb.funcSelectors[PUBLISH_PAIRS_SIG] = StudioProV1Storage.SelectorAdapter({ isActive: true, adapter: addressThis });
    }

    /// @notice Activate view function selectors in the vault (external function for manual activation)
    /// @dev Registers view function selectors so they can be called on the vault
    function activateViewFunctions() external {
        _activateViewFunctions();
    }

    // @notice Sets a new pair to the internal storage
    // @param token0 The address of the first token in the pair
    // @param token1 The address of the second token in the pair
    // @param feeBps The fee in basis points
    // @param chainlinkFeed0 The address of the chainlink feed for token0
    // @param chainlinkFeed1 The address of the chainlink feed for token1
    // @param dexes The array of DEX addresses for this pair
    function setPair(
        address token0,
        address token1,
        uint256 feeBps,
        address chainlinkFeed0,
        address chainlinkFeed1,
        address[] memory dexes
    ) public {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        // Get the pair hash
        bytes32 pairHash = keccak256(abi.encode(token0, token1));
        // Set the chainlink feeds
        $.chainlinkFeeds[token0] = chainlinkFeed0;
        $.chainlinkFeeds[token1] = chainlinkFeed1;
        // Check if the pair already exists
        if (!$.pairExists[pairHash]) {
            // Add the pair to the internal storage
            AquaAdapterStorage.Pair memory pair = AquaAdapterStorage.Pair({token0: token0, token1: token1, feeBps: feeBps, dexes: dexes});
            $.pairs.push(pair);
        } else {
            // Update existing pair's DEXes
            for (uint256 i = 0; i < $.pairs.length; i++) {
                bytes32 currentPairHash = keccak256(abi.encode($.pairs[i].token0, $.pairs[i].token1));
                if (currentPairHash == pairHash) {
                    // Clear existing DEXes array and add new ones
                    delete $.pairs[i].dexes;
                    for (uint256 j = 0; j < dexes.length; j++) {
                        $.pairs[i].dexes.push(dexes[j]);
                    }
                    break;
                }
            }
        }
        // Set the pair to true
        $.pairExists[pairHash] = true;
        // Emit the pair added event
        emit PairSet(token0, token1, feeBps, pairHash);
        // Activate view function selectors so they can be called on the vault
        _activateViewFunctions();
        // Publish the pair
        publishPairs();
    }

    // @notice Publish pairs on the Aqua protocol
    function publishPairs() public {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        for (uint256 i = 0; i < $.pairs.length; i++) {
            if ($.pairs[i].token0 == address(0) || $.pairs[i].token1 == address(0)) continue;
            // Loop through all DEXes for this pair
            // Increment nonce only for the first DEX of each pair
            for (uint256 j = 0; j < $.pairs[i].dexes.length; j++) {
                if ($.pairs[i].dexes[j] == address(0)) continue;
                _shipStrategy($.pairs[i].token0, $.pairs[i].token1, $.pairs[i].feeBps, $.pairs[i].dexes[j], j == 0);
            }
        }
    }

    /// @notice Helper function to get token decimals
    function _getTokenDecimals(address token) internal view returns (uint8) {
        try IERC20Metadata(token).decimals() returns (uint8 decimals) {
            return decimals;
        } catch {
            return 18; // Default to 18 if decimals() is not available
        }
    }

    /// @notice Calculate amounts and prices for strategy
    function _calculateAmounts(address[] memory tokens, uint256 balance0, uint256 balance1)
        internal
        view
        returns (uint256[] memory amounts, uint256[] memory prices)
    {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        IAggregator feed0 = IAggregator($.chainlinkFeeds[tokens[0]]);
        IAggregator feed1 = IAggregator($.chainlinkFeeds[tokens[1]]);

        (, int256 price0Raw,,,) = feed0.latestRoundData();
        (, int256 price1Raw,,,) = feed1.latestRoundData();
        if (price0Raw <= 0 || price1Raw <= 0) revert INVALID_PRICE();

        uint256 price0 = uint256(price0Raw);
        uint256 price1 = uint256(price1Raw);
        uint8 token0Decimals = _getTokenDecimals(tokens[0]);
        uint8 token1Decimals = _getTokenDecimals(tokens[1]);

        // Calculate USD values with inline price decimals
        uint256 value0Scaled = (balance0 * price0 * (10 ** 18)) / ((10 ** token0Decimals) * (10 ** feed0.decimals()));
        uint256 value1Scaled = (balance1 * price1 * (10 ** 18)) / ((10 ** token1Decimals) * (10 ** feed1.decimals()));
        uint256 minValueScaled = value0Scaled < value1Scaled ? value0Scaled : value1Scaled;

        amounts = new uint256[](2);
        amounts[0] = (minValueScaled * (10 ** token0Decimals) * (10 ** feed0.decimals())) / (price0 * (10 ** 18));
        amounts[1] = (minValueScaled * (10 ** token1Decimals) * (10 ** feed1.decimals())) / (price1 * (10 ** 18));
        if (amounts[0] > balance0) amounts[0] = balance0;
        if (amounts[1] > balance1) amounts[1] = balance1;

        prices = new uint256[](2);
        prices[0] = price0;
        prices[1] = price1;
    }

    /// @notice Adds a new strategy to the Aqua protocol
    /// @param token0 The address of the first token in the pair
    /// @param token1 The address of the second token in the pair
    /// @param feeBps The fee in basis points
    /// @param dex The address of the DEX
    /// @param shouldIncrementNonce Whether to increment the nonce (only once per pair update)
    function _shipStrategy(address token0, address token1, uint256 feeBps, address dex, bool shouldIncrementNonce)
        internal
    {
        AquaAdapterStorage.AquaAdapterDS storage $ = AquaAdapterStorage.s();
        if (dex == address(0)) revert SWAP_APP_NOT_SET();
        // Get the pair hash
        address[] memory tokens = new address[](2);
        tokens[0] = token0;
        tokens[1] = token1;
        bytes32 pairHash = keccak256(abi.encode(token0, token1));
        // Increment the nonce for the pair only if requested (once per pair update)
        if (shouldIncrementNonce) {
            $.strategyNonces[pairHash]++;
        }
        // Check if the strategy already exists for this DEX
        if ($.strategies[pairHash][dex].strategyHash != bytes32(0)) {
            // Dock the strategy
            try aqua.dock(dex, $.strategies[pairHash][dex].strategyHash, tokens) {} catch {}
        }
        // Approve Aqua to transfer tokens (required for pull() during swaps)
        IERC20(tokens[0]).approve(address(aqua), type(uint256).max);
        IERC20(tokens[1]).approve(address(aqua), type(uint256).max);
        // Create the strategy
        AquaStrategy memory strategy = AquaStrategy({
            maker: address(this),
            token0: token0,
            token1: token1,
            feeBps: feeBps,
            salt: bytes32($.strategyNonces[pairHash])
        });
        // Calculate the amounts based on the internal balance
        uint256 balance0 = IERC20(tokens[0]).balanceOf(address(this));
        uint256 balance1 = IERC20(tokens[1]).balanceOf(address(this));

        (uint256[] memory amounts, uint256[] memory prices) = _calculateAmounts(tokens, balance0, balance1);

        bytes32 strategyHash = aqua.ship(dex, abi.encode(strategy), tokens, amounts);
        $.strategies[pairHash][dex] = AquaAdapterStorage.StrategyData(token0, token1, strategyHash, amounts, prices, balance0, balance1);
        // Emit the strategy shipped event
        emit StrategyShipped(pairHash, strategyHash);
    }
}
