// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.7;

import {Script, console} from "forge-std/Script.sol";
import {WavePointToken} from "../src/WavePointToken.sol";

/// @title DeployWavePointToken
/// @notice Script to deploy WavePointToken for 1Wave points system
contract DeployWavePointToken is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address minter = vm.envAddress("MINTER_ADDRESS");
        address accessControlManager = vm.envAddress("ACCESS_CONTROL_MANAGER_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);

        WavePointToken wavePointToken = new WavePointToken(
            "1Wave Points",
            "WAVE",
            minter,
            accessControlManager
        );

        vm.stopBroadcast();

        console.log("WavePointToken deployed at:", address(wavePointToken));
        console.log("Name: 1Wave Points");
        console.log("Symbol: WAVE");
        console.log("Minter:", minter);
        console.log("AccessControlManager:", accessControlManager);
    }
}
