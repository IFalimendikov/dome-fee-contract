// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../contracts/DomeFeeEscrow.sol";

/**
 * @title Deploy
 * @notice Deployment script for DomeFeeEscrow
 * 
 * Usage:
 *   # Dry run
 *   forge script scripts/Deploy.s.sol --rpc-url $RPC_URL
 * 
 *   # Deploy
 *   forge script scripts/Deploy.s.sol --rpc-url $RPC_URL --broadcast
 * 
 *   # Deploy and verify
 *   forge script scripts/Deploy.s.sol --rpc-url $RPC_URL --broadcast --verify
 * 
 * Environment Variables:
 *   PRIVATE_KEY   - Deployer private key
 *   USDC_ADDRESS  - USDC token address
 *   DOME_WALLET   - Dome wallet to receive fees
 */
contract Deploy is Script {
    function run() external {
        // Load configuration from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address usdcAddress = vm.envAddress("USDC_ADDRESS");
        address domeWallet = vm.envAddress("DOME_WALLET");

        console.log("Deploying DomeFeeEscrow...");
        console.log("  USDC Address:", usdcAddress);
        console.log("  Dome Wallet:", domeWallet);

        vm.startBroadcast(deployerPrivateKey);

        DomeFeeEscrow escrow = new DomeFeeEscrow(usdcAddress, domeWallet);

        vm.stopBroadcast();

        console.log("");
        console.log("DomeFeeEscrow deployed at:", address(escrow));
        console.log("");
        console.log("Post-deployment checklist:");
        console.log("  1. Verify contract on block explorer");
        console.log("  2. Add operator addresses via addOperator()");
        console.log("  3. Review default fee settings (0.1%, min $0.01)");
        console.log("  4. Update backend with contract address");
    }
}

/**
 * @title DeployTestnet
 * @notice Testnet deployment with hardcoded addresses
 */
contract DeployTestnet is Script {
    // Sepolia USDC (Circle)
    address constant SEPOLIA_USDC = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address domeWallet = vm.envOr("DOME_WALLET", msg.sender);

        console.log("Deploying DomeFeeEscrow to Sepolia...");

        vm.startBroadcast(deployerPrivateKey);

        DomeFeeEscrow escrow = new DomeFeeEscrow(SEPOLIA_USDC, domeWallet);

        vm.stopBroadcast();

        console.log("DomeFeeEscrow deployed at:", address(escrow));
    }
}
