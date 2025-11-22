// SPDX-License-Identifier: LicenseRef-Degensoft-Aqua-Source-1.1
pragma solidity 0.8.30;

/// @custom:license-url https://github.com/1inch/aqua-app-template/blob/main/LICENSES/Aqua-Source-1.1.txt
/// @custom:copyright © 2025 Degensoft Ltd

import {Script} from "forge-std/Script.sol";
import {WaveSwap} from "../src/WaveSwap.sol";
import {IAqua} from "@1inch/aqua/src/interfaces/IAqua.sol";

// solhint-disable no-console
import {console2} from "forge-std/console2.sol";

/// @title DeployWaveSwap
/// @notice Deployment script for WaveSwap contract
contract DeployWaveSwap is Script {
    /// @notice Default Aqua contract address on Base
    /// @dev Update this for different networks
    address public constant DEFAULT_AQUA_ADDRESS = 0x499943E74FB0cE105688beeE8Ef2ABec5D936d31;

    /// @notice Run the deployment script
    /// @dev Can override Aqua address via environment variable AQUA_ADDRESS
    function run() external {
        // Get Aqua address from environment variable or use default
        address aquaAddress = vm.envOr("AQUA_ADDRESS", DEFAULT_AQUA_ADDRESS);
        
        require(aquaAddress != address(0), "AQUA_ADDRESS cannot be zero");

        vm.startBroadcast();

        // Deploy WaveSwap with Aqua contract address
        WaveSwap waveSwap = new WaveSwap(IAqua(aquaAddress));

        vm.stopBroadcast();

        console2.log("==========================================");
        console2.log("WaveSwap Deployment");
        console2.log("==========================================");
        console2.log("WaveSwap deployed at:", address(waveSwap));
        console2.log("Aqua address:", aquaAddress);
        console2.log("==========================================");
    }
}
// solhint-enable no-console

