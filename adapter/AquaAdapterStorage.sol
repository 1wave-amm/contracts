// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

library AquaAdapterStorage {
    struct StrategyData {
        address token0;
        address token1;
        bytes32 strategyHash;
        uint256[] amounts;
        uint256[] prices;
        uint256 liquidity0;
        uint256 liquidity1;
    }

    struct Pair {
        address token0;
        address token1;
        uint256 feeBps;
        address[] dexes;
    }

    struct AquaAdapterDS {
        mapping(bytes32 => mapping(address => StrategyData)) strategies;
        mapping(bytes32 => uint256) strategyNonces;
        mapping(bytes32 => bool) pairExists;
        mapping(address => address) chainlinkFeeds;
        Pair[] pairs;
    }

    bytes32 constant AQUA_ADAPTER_STORAGE = keccak256("factor.studio.aqua.adapter.storage");

    function s() internal pure returns (AquaAdapterDS storage ds) {
        bytes32 slot = AQUA_ADAPTER_STORAGE;
        assembly {
            ds.slot := slot
        }
    }
}
