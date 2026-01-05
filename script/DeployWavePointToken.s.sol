// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.7;

import {Script, console} from "forge-std/Script.sol";
import {WavePointToken} from "../src/WavePointToken.sol";

/// @title DeployWavePointToken
/// @notice Script to deploy WavePointToken for 1Wave points system
contract DeployWavePointToken is Script {
    function run() external {
        // Handle private key with or without 0x prefix
        string memory privateKeyStr = vm.envString("PRIVATE_KEY");
        uint256 deployerPrivateKey;
        if (bytes(privateKeyStr)[0] == 0x30 && bytes(privateKeyStr)[1] == 0x78) {
            // Has 0x prefix, remove it
            deployerPrivateKey = vm.parseUint(privateKeyStr);
        } else {
            // No prefix, add it
            string memory keyWithPrefix = string.concat("0x", privateKeyStr);
            deployerPrivateKey = vm.parseUint(keyWithPrefix);
        }
        
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
