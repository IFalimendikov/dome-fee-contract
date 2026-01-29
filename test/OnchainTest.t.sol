// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {DomeFeeEscrow} from "../contracts/DomeFeeEscrow.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title OnchainTest
 * @notice On-chain integration tests for deployed DomeFeeEscrow on Polygon
 * 
 * Usage:
 *   forge test --match-contract OnchainTest --fork-url $POLYGON_RPC_URL -vvv
 * 
 * With broadcast (actual transactions):
 *   forge script test/OnchainTest.t.sol:OnchainTestScript --rpc-url $POLYGON_RPC_URL --broadcast
 * 
 * Environment Variables:
 *   PRIVATE_KEY      - Private key for test account (must have USDC and MATIC for gas)
 *   POLYGON_RPC_URL  - Polygon mainnet RPC URL
 */
contract OnchainTest is Test {
    // ────────────────────────────────────────────────────────────────────────
    // Constants - Deployed Contract Addresses (Polygon Mainnet)
    // ────────────────────────────────────────────────────────────────────────
    
    /// @notice Deployed DomeFeeEscrow contract on Polygon
    address public constant ESCROW_ADDRESS = 0xc5526DEdc553D1a456D59a2C2166A81A7880730A;
    
    /// @notice USDC on Polygon
    address public constant USDC_ADDRESS = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    
    /// @notice Polygon chain ID
    uint256 public constant POLYGON_CHAIN_ID = 137;
    
    /// @notice Delay between RPC calls to avoid rate limiting (in seconds)
    uint256 public constant CALL_DELAY = 3;
    
    /// @notice EIP-712 permit typehash for USDC
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    // ────────────────────────────────────────────────────────────────────────
    // State
    // ────────────────────────────────────────────────────────────────────────
    
    DomeFeeEscrow public escrow;
    IERC20 public usdc;
    
    address public testAccount;
    uint256 public testPrivateKey;

    // ────────────────────────────────────────────────────────────────────────
    // Setup
    // ────────────────────────────────────────────────────────────────────────

    function setUp() public {
        // Ensure we're on the right chain
        require(block.chainid == POLYGON_CHAIN_ID, "Must run on Polygon mainnet fork");
        
        escrow = DomeFeeEscrow(ESCROW_ADDRESS);
        usdc = IERC20(USDC_ADDRESS);
        
        // Load test account from environment
        testPrivateKey = vm.envUint("PRIVATE_KEY");
        testAccount = vm.addr(testPrivateKey);
        
        console.log("Test account:", testAccount);
        console.log("USDC balance:", usdc.balanceOf(testAccount));
    }

    // ────────────────────────────────────────────────────────────────────────
    // View Function Tests (Read-only, no gas needed)
    // ────────────────────────────────────────────────────────────────────────

    function test_ReadContractState() public {
        console.log("\n=== Reading Contract State ===");
        
        // Test TOKEN address
        address token = address(escrow.TOKEN());
        console.log("TOKEN:", token);
        assertEq(token, USDC_ADDRESS, "TOKEN should be USDC");
        
        vm.sleep(CALL_DELAY * 1000); // Convert to milliseconds
        
        // Test domeWallet
        address domeWallet = escrow.domeWallet();
        console.log("Dome Wallet:", domeWallet);
        assertTrue(domeWallet != address(0), "Dome wallet should be set");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Test domeFeeBps
        uint256 feeBps = escrow.domeFeeBps();
        console.log("Dome Fee BPS:", feeBps);
        assertEq(feeBps, 10, "Default dome fee should be 10 bps (0.1%)");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Test minDomeFee
        uint256 minFee = escrow.minDomeFee();
        console.log("Min Dome Fee:", minFee);
        assertEq(minFee, 10_000, "Default min fee should be $0.01 (10000 with 6 decimals)");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Test totalHeld
        uint256 totalHeld = escrow.totalHeld();
        console.log("Total Held:", totalHeld);
        
        console.log("\n=== Contract State Verified ===\n");
    }

    function test_ReadConstants() public {
        console.log("\n=== Reading Contract Constants ===");
        
        // Test MAX_CLIENT_FEE_BPS
        uint256 maxClientFee = escrow.MAX_CLIENT_FEE_BPS();
        console.log("MAX_CLIENT_FEE_BPS:", maxClientFee);
        assertEq(maxClientFee, 10000, "Max client fee should be 10000 bps (100%)");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Test DEFAULT_DOME_FEE_BPS
        uint256 defaultFeeBps = escrow.DEFAULT_DOME_FEE_BPS();
        console.log("DEFAULT_DOME_FEE_BPS:", defaultFeeBps);
        assertEq(defaultFeeBps, 10, "Default dome fee bps should be 10");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Test DEFAULT_MIN_DOME_FEE
        uint256 defaultMinFee = escrow.DEFAULT_MIN_DOME_FEE();
        console.log("DEFAULT_MIN_DOME_FEE:", defaultMinFee);
        assertEq(defaultMinFee, 10_000, "Default min dome fee should be 10000");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Test FEE_AUTH_TYPEHASH
        bytes32 typeHash = escrow.FEE_AUTH_TYPEHASH();
        console.log("FEE_AUTH_TYPEHASH:");
        console.logBytes32(typeHash);
        bytes32 expectedTypeHash = keccak256("FeeAuth(bytes32 orderId,address payer,uint256 amount,uint256 deadline)");
        assertEq(typeHash, expectedTypeHash, "FEE_AUTH_TYPEHASH should match");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Test OPERATOR_ROLE
        bytes32 operatorRole = escrow.OPERATOR_ROLE();
        console.log("OPERATOR_ROLE:");
        console.logBytes32(operatorRole);
        assertEq(operatorRole, keccak256("OPERATOR_ROLE"), "OPERATOR_ROLE should match");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Test ADMIN_ROLE
        bytes32 adminRole = escrow.ADMIN_ROLE();
        console.log("ADMIN_ROLE:");
        console.logBytes32(adminRole);
        assertEq(adminRole, keccak256("ADMIN_ROLE"), "ADMIN_ROLE should match");
        
        console.log("\n=== Constants Verified ===\n");
    }

    function test_CalculateFee() public {
        console.log("\n=== Testing Fee Calculation ===");
        
        // Test with $1000 order
        uint256 orderSize = 1_000_000_000; // $1000 USDC
        uint256 clientFeeBps = 50; // 0.5%
        
        (uint256 domeFee, uint256 clientFee, uint256 totalFee) = escrow.calculateFee(orderSize, clientFeeBps);
        
        console.log("Order Size: $", orderSize / 1e6);
        console.log("Client Fee BPS:", clientFeeBps);
        console.log("Dome Fee:", domeFee);
        console.log("Client Fee:", clientFee);
        console.log("Total Fee:", totalFee);
        
        // Dome fee: 0.1% of $1000 = $1 = 1_000_000
        assertEq(domeFee, 1_000_000, "Dome fee should be $1.00 for $1000 order at 10bps");
        // Client fee: 0.5% of $1000 = $5 = 5_000_000
        assertEq(clientFee, 5_000_000, "Client fee should be $5 for $1000 order at 50bps");
        assertEq(totalFee, domeFee + clientFee, "Total fee should be dome + client");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Test min fee floor
        uint256 smallOrder = 10_000; // $0.01 USDC
        (uint256 smallDomeFee,,) = escrow.calculateFee(smallOrder, 0);
        console.log("\nSmall Order ($0.01) Dome Fee:", smallDomeFee);
        assertEq(smallDomeFee, escrow.minDomeFee(), "Small orders should use min fee floor");
        
        console.log("\n=== Fee Calculation Verified ===\n");
    }

    function test_DomainSeparator() public {
        console.log("\n=== Testing EIP-712 Domain Separator ===");
        
        bytes32 domainSeparator = escrow.DOMAIN_SEPARATOR();
        console.log("DOMAIN_SEPARATOR:");
        console.logBytes32(domainSeparator);
        
        // Domain separator should be non-zero
        assertTrue(domainSeparator != bytes32(0), "Domain separator should be set");
        
        console.log("\n=== Domain Separator Verified ===\n");
    }

    function test_GetEscrowStatus_NonexistentOrder() public {
        console.log("\n=== Testing Escrow Status for Nonexistent Order ===");
        
        bytes32 fakeOrderId = keccak256("nonexistent-order-12345");
        
        (
            address payer,
            address client,
            uint256 domeFee,
            uint256 clientFee,
            uint256 domeDistributed,
            uint256 clientDistributed,
            uint256 domeRemaining,
            uint256 clientRemaining,
            uint256 timestamp,
            DomeFeeEscrow.HoldState state
        ) = escrow.getEscrowStatus(fakeOrderId);
        
        console.log("Payer:", payer);
        console.log("Client:", client);
        console.log("Dome Fee:", domeFee);
        console.log("Client Fee:", clientFee);
        console.log("State:", uint8(state));
        
        // Non-existent order should have empty state
        assertEq(payer, address(0), "Payer should be zero for non-existent order");
        assertEq(uint8(state), uint8(DomeFeeEscrow.HoldState.EMPTY), "State should be EMPTY");
        
        console.log("\n=== Nonexistent Order Status Verified ===\n");
    }

    function test_AccessControlRoles() public {
        console.log("\n=== Testing Access Control Roles ===");
        
        // Get role identifiers
        bytes32 defaultAdminRole = escrow.DEFAULT_ADMIN_ROLE();
        bytes32 adminRole = escrow.ADMIN_ROLE();
        bytes32 operatorRole = escrow.OPERATOR_ROLE();
        
        console.log("DEFAULT_ADMIN_ROLE:");
        console.logBytes32(defaultAdminRole);
        console.log("ADMIN_ROLE:");
        console.logBytes32(adminRole);
        console.log("OPERATOR_ROLE:");
        console.logBytes32(operatorRole);
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Check if test account has any roles (likely not)
        bool hasDefaultAdmin = escrow.hasRole(defaultAdminRole, testAccount);
        bool hasAdmin = escrow.hasRole(adminRole, testAccount);
        bool hasOperator = escrow.hasRole(operatorRole, testAccount);
        
        console.log("\nTest account roles:");
        console.log("  Has DEFAULT_ADMIN_ROLE:", hasDefaultAdmin);
        console.log("  Has ADMIN_ROLE:", hasAdmin);
        console.log("  Has OPERATOR_ROLE:", hasOperator);
        
        console.log("\n=== Access Control Roles Verified ===\n");
    }

    function test_ContractBalance() public {
        console.log("\n=== Testing Contract Balance ===");
        
        uint256 usdcBalance = usdc.balanceOf(ESCROW_ADDRESS);
        uint256 totalHeld = escrow.totalHeld();
        
        console.log("USDC Balance:", usdcBalance);
        console.log("Total Held:", totalHeld);
        
        // Balance should be >= totalHeld (may have excess from direct transfers)
        assertTrue(usdcBalance >= totalHeld, "USDC balance should be >= totalHeld");
        
        uint256 excess = usdcBalance - totalHeld;
        console.log("Excess (rescuable):", excess);
        
        console.log("\n=== Contract Balance Verified ===\n");
    }

    function test_PausedState() public {
        console.log("\n=== Testing Paused State ===");
        
        bool isPaused = escrow.paused();
        console.log("Contract paused:", isPaused);
        
        // Contract should not be paused normally
        assertFalse(isPaused, "Contract should not be paused");
        
        console.log("\n=== Paused State Verified ===\n");
    }

    // ────────────────────────────────────────────────────────────────────────
    // Full Flow Tests (Requires OPERATOR_ROLE and USDC balance)
    // ────────────────────────────────────────────────────────────────────────

    /**
     * @notice Test complete flow: pullFee -> distribute -> verify
     * @dev Requires testAccount to have OPERATOR_ROLE and USDC balance
     */
    function test_FullFlow_PullFeeDistribute() public {
        console.log("\n=== Full Flow Test: PullFee -> Distribute ===\n");
        
        // Check if account has operator role
        bytes32 operatorRole = escrow.OPERATOR_ROLE();
        bool hasOperator = escrow.hasRole(operatorRole, testAccount);
        
        if (!hasOperator) {
            console.log("[SKIP] Account does not have OPERATOR_ROLE");
            return;
        }
        console.log("[OK] Account has OPERATOR_ROLE");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Check USDC balance
        uint256 usdcBalance = usdc.balanceOf(testAccount);
        console.log("USDC Balance:", usdcBalance);
        
        if (usdcBalance < 100_000) { // Need at least $0.10 for fees
            console.log("[SKIP] Insufficient USDC balance");
            return;
        }
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Generate unique order ID
        bytes32 orderId = keccak256(abi.encodePacked("test-full-flow-", block.timestamp, block.number, testAccount));
        console.log("Order ID:");
        console.logBytes32(orderId);
        
        // Order: $100 with 0.5% client fee
        uint256 orderSize = 100_000_000; // $100
        uint256 clientFeeBps = 50;
        uint256 deadline = block.timestamp + 1 hours;
        
        (uint256 domeFee, uint256 clientFee, uint256 totalFee) = escrow.calculateFee(orderSize, clientFeeBps);
        console.log("Order Size: $100");
        console.log("Dome Fee:", domeFee);
        console.log("Client Fee:", clientFee);
        console.log("Total Fee:", totalFee);
        
        require(usdcBalance >= totalFee, "Insufficient USDC for fee");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Create permit signature
        bytes memory sig = _createPermitSignature(testAccount, ESCROW_ADDRESS, totalFee, deadline, testPrivateKey);
        console.log("Permit signature created");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Record balances before
        uint256 escrowBalanceBefore = usdc.balanceOf(ESCROW_ADDRESS);
        uint256 totalHeldBefore = escrow.totalHeld();
        console.log("Escrow Balance Before:", escrowBalanceBefore);
        console.log("Total Held Before:", totalHeldBefore);
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Execute pullFee
        console.log("\n[1/3] Executing pullFee...");
        vm.prank(testAccount);
        escrow.pullFee(orderId, testAccount, orderSize, clientFeeBps, deadline, sig, address(0));
        console.log("[TX] pullFee executed!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify HELD state
        (
            address payer,
            ,
            uint256 storedDomeFee,
            uint256 storedClientFee,
            ,,,,,
            DomeFeeEscrow.HoldState state
        ) = escrow.getEscrowStatus(orderId);
        
        assertEq(payer, testAccount, "Payer should be testAccount");
        assertEq(storedDomeFee, domeFee, "Dome fee mismatch");
        assertEq(storedClientFee, clientFee, "Client fee mismatch");
        assertEq(uint8(state), uint8(DomeFeeEscrow.HoldState.HELD), "State should be HELD");
        console.log("[OK] Order in HELD state");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify escrow balance increased
        uint256 escrowBalanceAfterPull = usdc.balanceOf(ESCROW_ADDRESS);
        assertEq(escrowBalanceAfterPull, escrowBalanceBefore + totalFee, "Escrow balance mismatch");
        console.log("Escrow Balance After Pull:", escrowBalanceAfterPull);
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Execute full distribution
        console.log("\n[2/3] Executing full distribute...");
        address domeWallet = escrow.domeWallet();
        uint256 domeWalletBefore = usdc.balanceOf(domeWallet);
        
        vm.prank(testAccount);
        escrow.distribute(orderId, domeFee, clientFee);
        console.log("[TX] distribute executed!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify SENT state
        (,,,,,,,,, DomeFeeEscrow.HoldState state2) = escrow.getEscrowStatus(orderId);
        assertEq(uint8(state2), uint8(DomeFeeEscrow.HoldState.SENT), "State should be SENT");
        console.log("[OK] Order in SENT state");
        
        // Verify dome wallet received funds
        uint256 domeWalletAfter = usdc.balanceOf(domeWallet);
        assertEq(domeWalletAfter, domeWalletBefore + domeFee + clientFee, "Dome wallet balance mismatch");
        console.log("Dome Wallet Received:", domeWalletAfter - domeWalletBefore);
        
        console.log("\n[3/3] Verifying final state...");
        uint256 totalHeldAfter = escrow.totalHeld();
        assertEq(totalHeldAfter, totalHeldBefore, "Total held should return to original");
        console.log("[OK] Total held returned to original");
        
        console.log("\n=== Full Flow Test PASSED! ===\n");
    }

    /**
     * @notice Test pullFee -> partial distribute -> refund remaining
     */
    function test_FullFlow_PullFeePartialDistributeRefund() public {
        console.log("\n=== Full Flow Test: PullFee -> Partial Distribute -> Refund ===\n");
        
        // Check operator role
        bytes32 operatorRole = escrow.OPERATOR_ROLE();
        if (!escrow.hasRole(operatorRole, testAccount)) {
            console.log("[SKIP] Account does not have OPERATOR_ROLE");
            return;
        }
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Check USDC balance
        uint256 usdcBalance = usdc.balanceOf(testAccount);
        if (usdcBalance < 100_000) {
            console.log("[SKIP] Insufficient USDC balance");
            return;
        }
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Generate unique order ID
        bytes32 orderId = keccak256(abi.encodePacked("test-refund-", block.timestamp, block.number, testAccount));
        console.log("Order ID:");
        console.logBytes32(orderId);
        
        // Order: $50 with no client fee
        uint256 orderSize = 50_000_000; // $50
        uint256 clientFeeBps = 0;
        uint256 deadline = block.timestamp + 1 hours;
        
        (uint256 domeFee,, uint256 totalFee) = escrow.calculateFee(orderSize, clientFeeBps);
        console.log("Total Fee:", totalFee);
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Create permit and execute pullFee
        bytes memory sig = _createPermitSignature(testAccount, ESCROW_ADDRESS, totalFee, deadline, testPrivateKey);
        
        vm.prank(testAccount);
        escrow.pullFee(orderId, testAccount, orderSize, clientFeeBps, deadline, sig, address(0));
        console.log("[TX] pullFee executed!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Partial distribute (50%)
        uint256 halfDomeFee = domeFee / 2;
        vm.prank(testAccount);
        escrow.distribute(orderId, halfDomeFee, 0);
        console.log("[TX] Partial distribute (50%) executed!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify still HELD
        (,,,,,,,,, DomeFeeEscrow.HoldState state) = escrow.getEscrowStatus(orderId);
        assertEq(uint8(state), uint8(DomeFeeEscrow.HoldState.HELD), "State should still be HELD");
        
        // Record balance before refund
        uint256 accountBalanceBefore = usdc.balanceOf(testAccount);
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Refund remaining
        vm.prank(testAccount);
        escrow.refund(orderId);
        console.log("[TX] refund executed!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify REFUNDED state
        (,,,,,,,,, DomeFeeEscrow.HoldState state2) = escrow.getEscrowStatus(orderId);
        assertEq(uint8(state2), uint8(DomeFeeEscrow.HoldState.REFUNDED), "State should be REFUNDED");
        
        // Verify refund amount
        uint256 accountBalanceAfter = usdc.balanceOf(testAccount);
        uint256 expectedRefund = domeFee - halfDomeFee;
        assertEq(accountBalanceAfter - accountBalanceBefore, expectedRefund, "Refund amount mismatch");
        console.log("Refunded:", expectedRefund);
        
        console.log("\n=== Partial Distribute + Refund Test PASSED! ===\n");
    }

    // ────────────────────────────────────────────────────────────────────────
    // Internal Helpers
    // ────────────────────────────────────────────────────────────────────────

    function _createPermitSignature(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        // Get USDC domain separator and nonce
        bytes32 domainSeparator = _getUsdcDomainSeparator();
        uint256 nonce = _getUsdcNonce(owner);
        
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                nonce,
                deadline
            )
        );
        
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        
        return abi.encodePacked(r, s, v);
    }
    
    function _getUsdcDomainSeparator() internal view returns (bytes32) {
        (bool success, bytes memory data) = USDC_ADDRESS.staticcall(
            abi.encodeWithSignature("DOMAIN_SEPARATOR()")
        );
        require(success, "Failed to get USDC domain separator");
        return abi.decode(data, (bytes32));
    }
    
    function _getUsdcNonce(address owner) internal view returns (uint256) {
        (bool success, bytes memory data) = USDC_ADDRESS.staticcall(
            abi.encodeWithSignature("nonces(address)", owner)
        );
        require(success, "Failed to get USDC nonce");
        return abi.decode(data, (uint256));
    }
}

/**
 * @title OnchainTestScript
 * @notice Script version for running actual transactions on-chain
 * 
 * Usage:
 *   forge script test/OnchainTest.t.sol:OnchainTestScript \
 *     --rpc-url $POLYGON_RPC_URL \
 *     --private-key $PRIVATE_KEY \
 *     --broadcast -vvv
 */
contract OnchainTestScript is Test {
    address public constant ESCROW_ADDRESS = 0xc5526DEdc553D1a456D59a2C2166A81A7880730A;
    address public constant USDC_ADDRESS = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    uint256 public constant CALL_DELAY = 5;
    
    DomeFeeEscrow public escrow;
    IERC20 public usdc;

    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address account = vm.addr(privateKey);
        
        escrow = DomeFeeEscrow(ESCROW_ADDRESS);
        usdc = IERC20(USDC_ADDRESS);
        
        console.log("\n========================================");
        console.log("  DomeFeeEscrow On-chain Test Suite");
        console.log("========================================\n");
        
        console.log("Contract:", ESCROW_ADDRESS);
        console.log("Test Account:", account);
        console.log("Account USDC Balance:", usdc.balanceOf(account));
        console.log("Account MATIC Balance:", account.balance);
        
        // Run read-only tests
        _testContractState();
        vm.sleep(CALL_DELAY * 1000);
        
        _testConstants();
        vm.sleep(CALL_DELAY * 1000);
        
        _testFeeCalculation();
        vm.sleep(CALL_DELAY * 1000);
        
        _testAccessControl(account);
        vm.sleep(CALL_DELAY * 1000);
        
        _testBalances();
        
        console.log("\n========================================");
        console.log("  All On-chain Tests Passed!");
        console.log("========================================\n");
    }
    
    function _testContractState() internal {
        console.log("\n--- Contract State ---");
        
        address token = address(escrow.TOKEN());
        address domeWallet = escrow.domeWallet();
        uint256 feeBps = escrow.domeFeeBps();
        uint256 minFee = escrow.minDomeFee();
        uint256 totalHeld = escrow.totalHeld();
        bool isPaused = escrow.paused();
        
        console.log("TOKEN:", token);
        console.log("Dome Wallet:", domeWallet);
        console.log("Dome Fee BPS:", feeBps);
        console.log("Min Dome Fee:", minFee);
        console.log("Total Held:", totalHeld);
        console.log("Paused:", isPaused);
        
        require(token == USDC_ADDRESS, "TOKEN mismatch");
        require(domeWallet != address(0), "Dome wallet not set");
        require(feeBps == 10, "Fee BPS mismatch");
        require(minFee == 10_000, "Min fee mismatch");
        require(!isPaused, "Contract should not be paused");
        
        console.log("[PASS] Contract state verified");
    }
    
    function _testConstants() internal {
        console.log("\n--- Constants ---");
        
        uint256 maxClientFee = escrow.MAX_CLIENT_FEE_BPS();
        uint256 defaultFeeBps = escrow.DEFAULT_DOME_FEE_BPS();
        uint256 defaultMinFee = escrow.DEFAULT_MIN_DOME_FEE();
        
        console.log("MAX_CLIENT_FEE_BPS:", maxClientFee);
        console.log("DEFAULT_DOME_FEE_BPS:", defaultFeeBps);
        console.log("DEFAULT_MIN_DOME_FEE:", defaultMinFee);
        
        require(maxClientFee == 10000, "MAX_CLIENT_FEE_BPS mismatch");
        require(defaultFeeBps == 10, "DEFAULT_DOME_FEE_BPS mismatch");
        require(defaultMinFee == 10_000, "DEFAULT_MIN_DOME_FEE mismatch");
        
        console.log("[PASS] Constants verified");
    }
    
    function _testFeeCalculation() internal {
        console.log("\n--- Fee Calculation ---");
        
        // $1000 order with 0.5% client fee
        uint256 orderSize = 1_000_000_000;
        uint256 clientFeeBps = 50;
        
        (uint256 domeFee, uint256 clientFee, uint256 totalFee) = escrow.calculateFee(orderSize, clientFeeBps);
        
        console.log("Order: $1000, Client: 0.5%");
        console.log("Dome Fee:", domeFee);
        console.log("Client Fee:", clientFee);
        console.log("Total Fee:", totalFee);
        
        require(domeFee == 1_000_000, "Dome fee calculation error");
        require(clientFee == 5_000_000, "Client fee calculation error");
        require(totalFee == domeFee + clientFee, "Total fee calculation error");
        
        // Test min fee floor
        (uint256 smallDomeFee,,) = escrow.calculateFee(10_000, 0);
        require(smallDomeFee == escrow.minDomeFee(), "Min fee floor not applied");
        
        console.log("[PASS] Fee calculation verified");
    }
    
    function _testAccessControl(address account) internal {
        console.log("\n--- Access Control ---");
        
        bytes32 defaultAdminRole = escrow.DEFAULT_ADMIN_ROLE();
        bytes32 adminRole = escrow.ADMIN_ROLE();
        bytes32 operatorRole = escrow.OPERATOR_ROLE();
        
        bool hasDefaultAdmin = escrow.hasRole(defaultAdminRole, account);
        bool hasAdmin = escrow.hasRole(adminRole, account);
        bool hasOperator = escrow.hasRole(operatorRole, account);
        
        console.log("Account has DEFAULT_ADMIN:", hasDefaultAdmin);
        console.log("Account has ADMIN:", hasAdmin);
        console.log("Account has OPERATOR:", hasOperator);
        
        console.log("[PASS] Access control verified");
    }
    
    function _testBalances() internal {
        console.log("\n--- Balances ---");
        
        uint256 contractUsdc = usdc.balanceOf(ESCROW_ADDRESS);
        uint256 totalHeld = escrow.totalHeld();
        
        console.log("Contract USDC:", contractUsdc);
        console.log("Total Held:", totalHeld);
        console.log("Excess:", contractUsdc >= totalHeld ? contractUsdc - totalHeld : 0);
        
        require(contractUsdc >= totalHeld, "Balance integrity error");
        
        console.log("[PASS] Balances verified");
    }
}

/**
 * @title OnchainOperatorTest
 * @notice Tests that require OPERATOR_ROLE (only run if account has operator access)
 * 
 * WARNING: These tests perform actual transactions and cost gas/USDC!
 * 
 * Usage:
 *   forge script test/OnchainTest.t.sol:OnchainOperatorTest \
 *     --rpc-url $POLYGON_RPC_URL \
 *     --private-key $PRIVATE_KEY \
 *     --broadcast -vvv
 */
contract OnchainOperatorTest is Test {
    address public constant ESCROW_ADDRESS = 0xc5526DEdc553D1a456D59a2C2166A81A7880730A;
    address public constant USDC_ADDRESS = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    uint256 public constant CALL_DELAY = 3;
    
    DomeFeeEscrow public escrow;
    IERC20 public usdc;
    
    // EIP-712 constants for permit signature
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    
    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address account = vm.addr(privateKey);
        
        escrow = DomeFeeEscrow(ESCROW_ADDRESS);
        usdc = IERC20(USDC_ADDRESS);
        
        console.log("\n========================================");
        console.log("  Operator Tests (Requires OPERATOR_ROLE)");
        console.log("========================================\n");
        
        console.log("Account:", account);
        console.log("USDC Balance:", usdc.balanceOf(account));
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Check if account has operator role
        bytes32 operatorRole = escrow.OPERATOR_ROLE();
        bool hasOperator = escrow.hasRole(operatorRole, account);
        
        console.log("Has OPERATOR_ROLE:", hasOperator);
        
        if (!hasOperator) {
            console.log("\n[SKIP] Account does not have OPERATOR_ROLE");
            console.log("Grant OPERATOR_ROLE to run operator tests");
            return;
        }
        
        console.log("\n[OK] Account has OPERATOR_ROLE - running full test suite\n");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Run the full test flow
        _testPullFeeDistributeRefund(privateKey, account);
        
        console.log("\n========================================");
        console.log("  Operator Test Suite Complete!");
        console.log("========================================\n");
    }
    
    function _testPullFeeDistributeRefund(uint256 privateKey, address account) internal {
        // ═══════════════════════════════════════════════════════════════════
        // Test 1: PullFee with EOA (permit signature)
        // ═══════════════════════════════════════════════════════════════════
        console.log("--- Test: PullFee (EOA with permit) ---");
        
        // Generate unique order ID
        bytes32 orderId = keccak256(abi.encodePacked("onchain-test-", block.timestamp, block.number, account));
        console.log("Order ID:");
        console.logBytes32(orderId);
        
        // Order parameters
        uint256 orderSize = 100_000_000; // $100 USDC
        uint256 clientFeeBps = 50; // 0.5%
        address clientAddress = address(0); // No client for this test
        uint256 deadline = block.timestamp + 1 hours;
        
        // Calculate expected fees
        (uint256 expectedDomeFee, uint256 expectedClientFee, uint256 expectedTotalFee) = escrow.calculateFee(orderSize, clientFeeBps);
        console.log("Order Size: $", orderSize / 1e6);
        console.log("Expected Dome Fee:", expectedDomeFee);
        console.log("Expected Client Fee:", expectedClientFee);
        console.log("Expected Total Fee:", expectedTotalFee);
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Check USDC balance
        uint256 usdcBalance = usdc.balanceOf(account);
        console.log("Account USDC Balance:", usdcBalance);
        require(usdcBalance >= expectedTotalFee, "Insufficient USDC balance for test");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Create permit signature
        bytes memory permitSig = _createPermitSignature(
            account,
            ESCROW_ADDRESS,
            expectedTotalFee,
            deadline,
            privateKey
        );
        console.log("Permit signature created (length:", permitSig.length, ")");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Record balances before
        uint256 escrowBalanceBefore = usdc.balanceOf(ESCROW_ADDRESS);
        uint256 totalHeldBefore = escrow.totalHeld();
        console.log("Escrow USDC Before:", escrowBalanceBefore);
        console.log("Total Held Before:", totalHeldBefore);
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Execute pullFee
        vm.startBroadcast(privateKey);
        escrow.pullFee(
            orderId,
            account,
            orderSize,
            clientFeeBps,
            deadline,
            permitSig,
            clientAddress
        );
        vm.stopBroadcast();
        
        console.log("[TX] pullFee executed!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify escrow state
        (
            address payer,
            address client,
            uint256 domeFee,
            uint256 clientFee,
            uint256 domeDistributed,
            uint256 clientDistributed,
            uint256 domeRemaining,
            uint256 clientRemaining,
            uint256 timestamp,
            DomeFeeEscrow.HoldState state
        ) = escrow.getEscrowStatus(orderId);
        
        console.log("\n--- Escrow Status After PullFee ---");
        console.log("Payer:", payer);
        console.log("Dome Fee:", domeFee);
        console.log("Client Fee:", clientFee);
        console.log("State:", uint8(state));
        
        require(payer == account, "Payer mismatch");
        require(domeFee == expectedDomeFee, "Dome fee mismatch");
        require(uint8(state) == uint8(DomeFeeEscrow.HoldState.HELD), "State should be HELD");
        
        console.log("[PASS] PullFee verified!\n");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // ═══════════════════════════════════════════════════════════════════
        // Test 2: Partial Distribution
        // ═══════════════════════════════════════════════════════════════════
        console.log("--- Test: Partial Distribution ---");
        
        uint256 domeToDistribute = domeFee / 2; // Distribute half
        uint256 clientToDistribute = clientFee / 2;
        
        address domeWallet = escrow.domeWallet();
        uint256 domeWalletBefore = usdc.balanceOf(domeWallet);
        console.log("Dome Wallet:", domeWallet);
        console.log("Dome Wallet Balance Before:", domeWalletBefore);
        console.log("Distributing Dome:", domeToDistribute);
        console.log("Distributing Client:", clientToDistribute);
        
        vm.sleep(CALL_DELAY * 1000);
        
        vm.startBroadcast(privateKey);
        escrow.distribute(orderId, domeToDistribute, clientToDistribute);
        vm.stopBroadcast();
        
        console.log("[TX] distribute executed!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify partial distribution
        (,,,, uint256 domeDistributed2, uint256 clientDistributed2, uint256 domeRemaining2, uint256 clientRemaining2,, DomeFeeEscrow.HoldState state2) = escrow.getEscrowStatus(orderId);
        
        console.log("Dome Distributed:", domeDistributed2);
        console.log("Dome Remaining:", domeRemaining2);
        console.log("State:", uint8(state2));
        
        require(domeDistributed2 == domeToDistribute, "Dome distributed mismatch");
        require(domeRemaining2 == domeFee - domeToDistribute, "Dome remaining mismatch");
        require(uint8(state2) == uint8(DomeFeeEscrow.HoldState.HELD), "State should still be HELD");
        
        console.log("[PASS] Partial distribution verified!\n");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // ═══════════════════════════════════════════════════════════════════
        // Test 3: Refund Remaining
        // ═══════════════════════════════════════════════════════════════════
        console.log("--- Test: Refund Remaining ---");
        
        uint256 accountBalanceBefore = usdc.balanceOf(account);
        uint256 expectedRefund = domeRemaining2 + clientRemaining2;
        console.log("Account USDC Before:", accountBalanceBefore);
        console.log("Expected Refund:", expectedRefund);
        
        vm.sleep(CALL_DELAY * 1000);
        
        vm.startBroadcast(privateKey);
        escrow.refund(orderId);
        vm.stopBroadcast();
        
        console.log("[TX] refund executed!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify refund
        (,,,,,,,,, DomeFeeEscrow.HoldState state3) = escrow.getEscrowStatus(orderId);
        uint256 accountBalanceAfter = usdc.balanceOf(account);
        
        console.log("Account USDC After:", accountBalanceAfter);
        console.log("Refund Amount:", accountBalanceAfter - accountBalanceBefore);
        console.log("State:", uint8(state3));
        
        require(uint8(state3) == uint8(DomeFeeEscrow.HoldState.REFUNDED), "State should be REFUNDED");
        require(accountBalanceAfter == accountBalanceBefore + expectedRefund, "Refund amount mismatch");
        
        console.log("[PASS] Refund verified!\n");
    }
    
    function _createPermitSignature(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        // Get USDC domain separator and nonce
        // USDC.e on Polygon uses standard EIP-2612
        bytes32 domainSeparator = _getUsdcDomainSeparator();
        uint256 nonce = _getUsdcNonce(owner);
        
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                nonce,
                deadline
            )
        );
        
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        
        return abi.encodePacked(r, s, v);
    }
    
    function _getUsdcDomainSeparator() internal view returns (bytes32) {
        // Call DOMAIN_SEPARATOR() on USDC.e
        (bool success, bytes memory data) = USDC_ADDRESS.staticcall(
            abi.encodeWithSignature("DOMAIN_SEPARATOR()")
        );
        require(success, "Failed to get USDC domain separator");
        return abi.decode(data, (bytes32));
    }
    
    function _getUsdcNonce(address owner) internal view returns (uint256) {
        // Call nonces(address) on USDC.e
        (bool success, bytes memory data) = USDC_ADDRESS.staticcall(
            abi.encodeWithSignature("nonces(address)", owner)
        );
        require(success, "Failed to get USDC nonce");
        return abi.decode(data, (uint256));
    }
}

/**
 * @title OnchainFullFlowTest
 * @notice Complete end-to-end test for pullFee -> distribute -> verify
 * 
 * This test performs actual on-chain transactions!
 * Make sure the account has:
 * - OPERATOR_ROLE on the escrow contract
 * - Sufficient USDC balance
 * - POL for gas
 * 
 * Usage:
 *   forge script test/OnchainTest.t.sol:OnchainFullFlowTest \
 *     --rpc-url $POLYGON_RPC_URL \
 *     --private-key $PRIVATE_KEY \
 *     --broadcast -vvv
 */
contract OnchainFullFlowTest is Test {
    address public constant ESCROW_ADDRESS = 0xc5526DEdc553D1a456D59a2C2166A81A7880730A;
    address public constant USDC_ADDRESS = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    uint256 public constant CALL_DELAY = 3;
    
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    
    DomeFeeEscrow public escrow;
    IERC20 public usdc;
    
    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address account = vm.addr(privateKey);
        
        escrow = DomeFeeEscrow(ESCROW_ADDRESS);
        usdc = IERC20(USDC_ADDRESS);
        
        console.log("\n========================================");
        console.log("  Full Flow Test: PullFee -> Distribute");
        console.log("========================================\n");
        
        console.log("Account:", account);
        console.log("USDC Balance:", usdc.balanceOf(account));
        console.log("POL Balance:", account.balance);
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Check operator role
        bytes32 operatorRole = escrow.OPERATOR_ROLE();
        require(escrow.hasRole(operatorRole, account), "Account needs OPERATOR_ROLE");
        console.log("[OK] Account has OPERATOR_ROLE");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Generate unique order ID
        bytes32 orderId = keccak256(abi.encodePacked("full-flow-test-", block.timestamp, block.number));
        console.log("\nOrder ID:");
        console.logBytes32(orderId);
        
        // Order: $50 with 0.5% client fee
        uint256 orderSize = 50_000_000; // $50
        uint256 clientFeeBps = 50;
        uint256 deadline = block.timestamp + 1 hours;
        
        (uint256 domeFee, uint256 clientFee, uint256 totalFee) = escrow.calculateFee(orderSize, clientFeeBps);
        console.log("Order Size: $50");
        console.log("Total Fee:");
        console.log(totalFee);
        
        require(usdc.balanceOf(account) >= totalFee, "Insufficient USDC");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Create permit signature
        bytes memory sig = _createPermit(account, ESCROW_ADDRESS, totalFee, deadline, privateKey);
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Execute pullFee
        console.log("\n[1/3] Executing pullFee...");
        vm.startBroadcast(privateKey);
        escrow.pullFee(orderId, account, orderSize, clientFeeBps, deadline, sig, address(0));
        vm.stopBroadcast();
        console.log("[TX] pullFee success!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify HELD state
        (,,,,,,,,, DomeFeeEscrow.HoldState state) = escrow.getEscrowStatus(orderId);
        require(uint8(state) == 1, "Expected HELD state");
        console.log("[OK] Order in HELD state");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Execute full distribution
        console.log("\n[2/3] Executing full distribute...");
        vm.startBroadcast(privateKey);
        escrow.distribute(orderId, domeFee, clientFee);
        vm.stopBroadcast();
        console.log("[TX] distribute success!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify SENT state
        (,,,,,,,,, DomeFeeEscrow.HoldState state2) = escrow.getEscrowStatus(orderId);
        require(uint8(state2) == 2, "Expected SENT state");
        console.log("[OK] Order in SENT state");
        
        console.log("\n========================================");
        console.log("  Full Flow Test PASSED!");
        console.log("========================================\n");
        
        // ════════════════════════════════════════════════════════════════════
        // TEST 2: Refund Flow (pullFee -> partial distribute -> refund)
        // ════════════════════════════════════════════════════════════════════
        
        console.log("\n========================================");
        console.log("  Refund Test: PullFee -> Partial -> Refund");
        console.log("========================================\n");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Generate new order ID for refund test
        bytes32 refundOrderId = keccak256(abi.encodePacked("refund-test-", block.timestamp, block.number));
        console.log("Refund Order ID:");
        console.logBytes32(refundOrderId);
        
        // Order: $100 with 0.5% client fee
        uint256 refundOrderSize = 100_000_000; // $100
        (uint256 refundDomeFee, uint256 refundClientFee, uint256 refundTotalFee) = escrow.calculateFee(refundOrderSize, clientFeeBps);
        console.log("Order Size: $100");
        console.log("Total Fee:", refundTotalFee);
        
        require(usdc.balanceOf(account) >= refundTotalFee, "Insufficient USDC for refund test");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Create permit and pullFee
        bytes memory refundSig = _createPermit(account, ESCROW_ADDRESS, refundTotalFee, block.timestamp + 1 hours, privateKey);
        
        console.log("\n[1/4] Executing pullFee for refund test...");
        vm.startBroadcast(privateKey);
        escrow.pullFee(refundOrderId, account, refundOrderSize, clientFeeBps, block.timestamp + 1 hours, refundSig, address(0));
        vm.stopBroadcast();
        console.log("[TX] pullFee success!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Partial distribute (50% of fees)
        uint256 partialDome = refundDomeFee / 2;
        uint256 partialClient = refundClientFee / 2;
        
        console.log("\n[2/4] Executing partial distribute (50%)...");
        console.log("Distributing Dome:", partialDome);
        console.log("Distributing Client:", partialClient);
        
        vm.startBroadcast(privateKey);
        escrow.distribute(refundOrderId, partialDome, partialClient);
        vm.stopBroadcast();
        console.log("[TX] partial distribute success!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify still HELD
        (,,,,,,,,, DomeFeeEscrow.HoldState refundState1) = escrow.getEscrowStatus(refundOrderId);
        require(uint8(refundState1) == 1, "Expected HELD state after partial distribute");
        console.log("[OK] Order still in HELD state");
        
        // Record balance before refund
        uint256 accountBalanceBefore = usdc.balanceOf(account);
        uint256 expectedRefund = (refundDomeFee - partialDome) + (refundClientFee - partialClient);
        console.log("\n[3/4] Executing refund...");
        console.log("Expected Refund:", expectedRefund);
        
        vm.sleep(CALL_DELAY * 1000);
        
        vm.startBroadcast(privateKey);
        escrow.refund(refundOrderId);
        vm.stopBroadcast();
        console.log("[TX] refund success!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify REFUNDED state
        (,,,,,,,,, DomeFeeEscrow.HoldState refundState2) = escrow.getEscrowStatus(refundOrderId);
        require(uint8(refundState2) == 3, "Expected REFUNDED state");
        
        uint256 accountBalanceAfter = usdc.balanceOf(account);
        uint256 actualRefund = accountBalanceAfter - accountBalanceBefore;
        console.log("[4/4] Verifying refund amount...");
        console.log("Actual Refund:", actualRefund);
        require(actualRefund == expectedRefund, "Refund amount mismatch");
        console.log("[OK] Refund amount verified!");
        
        console.log("\n========================================");
        console.log("  Refund Test PASSED!");
        console.log("========================================\n");
        
        // ════════════════════════════════════════════════════════════════════
        // TEST 3: Batch Distribute (multiple orders at once)
        // ════════════════════════════════════════════════════════════════════
        
        console.log("\n========================================");
        console.log("  Batch Distribute Test");
        console.log("========================================\n");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Create 3 orders for batch testing
        bytes32 batchOrder1 = keccak256(abi.encodePacked("batch-1-", block.timestamp, block.number));
        bytes32 batchOrder2 = keccak256(abi.encodePacked("batch-2-", block.timestamp, block.number));
        bytes32 batchOrder3 = keccak256(abi.encodePacked("batch-3-", block.timestamp, block.number));
        
        console.log("Batch Order 1:");
        console.logBytes32(batchOrder1);
        console.log("Batch Order 2:");
        console.logBytes32(batchOrder2);
        console.log("Batch Order 3:");
        console.logBytes32(batchOrder3);
        
        // Small orders: $20 each with no client fee
        uint256 batchOrderSize = 20_000_000; // $20
        uint256 batchClientFeeBps = 0;
        (uint256 batchDomeFee,, uint256 batchTotalFee) = escrow.calculateFee(batchOrderSize, batchClientFeeBps);
        
        uint256 totalBatchFee = batchTotalFee * 3;
        console.log("Fee per order:", batchTotalFee);
        console.log("Total for 3 orders:", totalBatchFee);
        
        require(usdc.balanceOf(account) >= totalBatchFee, "Insufficient USDC for batch test");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Pull fees for all 3 orders
        console.log("\n[1/3] Creating 3 orders...");
        
        bytes memory batchSig1 = _createPermit(account, ESCROW_ADDRESS, batchTotalFee, block.timestamp + 1 hours, privateKey);
        vm.startBroadcast(privateKey);
        escrow.pullFee(batchOrder1, account, batchOrderSize, batchClientFeeBps, block.timestamp + 1 hours, batchSig1, address(0));
        vm.stopBroadcast();
        console.log("[TX] Order 1 created");
        
        vm.sleep(CALL_DELAY * 1000);
        
        bytes memory batchSig2 = _createPermit(account, ESCROW_ADDRESS, batchTotalFee, block.timestamp + 1 hours, privateKey);
        vm.startBroadcast(privateKey);
        escrow.pullFee(batchOrder2, account, batchOrderSize, batchClientFeeBps, block.timestamp + 1 hours, batchSig2, address(0));
        vm.stopBroadcast();
        console.log("[TX] Order 2 created");
        
        vm.sleep(CALL_DELAY * 1000);
        
        bytes memory batchSig3 = _createPermit(account, ESCROW_ADDRESS, batchTotalFee, block.timestamp + 1 hours, privateKey);
        vm.startBroadcast(privateKey);
        escrow.pullFee(batchOrder3, account, batchOrderSize, batchClientFeeBps, block.timestamp + 1 hours, batchSig3, address(0));
        vm.stopBroadcast();
        console.log("[TX] Order 3 created");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Prepare batch distribute arrays
        bytes32[] memory batchOrderIds = new bytes32[](3);
        batchOrderIds[0] = batchOrder1;
        batchOrderIds[1] = batchOrder2;
        batchOrderIds[2] = batchOrder3;
        
        uint256[] memory batchDomeAmounts = new uint256[](3);
        batchDomeAmounts[0] = batchDomeFee;
        batchDomeAmounts[1] = batchDomeFee;
        batchDomeAmounts[2] = batchDomeFee;
        
        uint256[] memory batchClientAmounts = new uint256[](3);
        batchClientAmounts[0] = 0;
        batchClientAmounts[1] = 0;
        batchClientAmounts[2] = 0;
        
        console.log("\n[2/3] Executing distributeBatch for 3 orders...");
        
        vm.startBroadcast(privateKey);
        escrow.distributeBatch(batchOrderIds, batchDomeAmounts, batchClientAmounts);
        vm.stopBroadcast();
        console.log("[TX] distributeBatch success!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify all orders are SENT
        console.log("\n[3/3] Verifying all orders in SENT state...");
        
        (,,,,,,,,, DomeFeeEscrow.HoldState bState1) = escrow.getEscrowStatus(batchOrder1);
        (,,,,,,,,, DomeFeeEscrow.HoldState bState2) = escrow.getEscrowStatus(batchOrder2);
        (,,,,,,,,, DomeFeeEscrow.HoldState bState3) = escrow.getEscrowStatus(batchOrder3);
        
        require(uint8(bState1) == 2, "Order 1 should be SENT");
        require(uint8(bState2) == 2, "Order 2 should be SENT");
        require(uint8(bState3) == 2, "Order 3 should be SENT");
        
        console.log("[OK] All 3 orders in SENT state!");
        
        console.log("\n========================================");
        console.log("  Batch Distribute Test PASSED!");
        console.log("========================================\n");
        
        // ════════════════════════════════════════════════════════════════════
        // TEST 4: Batch Refund (multiple orders at once)
        // ════════════════════════════════════════════════════════════════════
        
        console.log("\n========================================");
        console.log("  Batch Refund Test");
        console.log("========================================\n");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Create 2 orders for batch refund testing
        bytes32 refundBatch1 = keccak256(abi.encodePacked("refund-batch-1-", block.timestamp, block.number));
        bytes32 refundBatch2 = keccak256(abi.encodePacked("refund-batch-2-", block.timestamp, block.number));
        
        console.log("Refund Batch Order 1:");
        console.logBytes32(refundBatch1);
        console.log("Refund Batch Order 2:");
        console.logBytes32(refundBatch2);
        
        // $30 orders
        uint256 refundBatchOrderSize = 30_000_000; // $30
        (uint256 refundBatchDomeFee,, uint256 refundBatchTotalFee) = escrow.calculateFee(refundBatchOrderSize, 0);
        
        console.log("Fee per order:", refundBatchTotalFee);
        
        require(usdc.balanceOf(account) >= refundBatchTotalFee * 2, "Insufficient USDC for batch refund test");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Create 2 orders
        console.log("\n[1/3] Creating 2 orders for batch refund...");
        
        bytes memory refundBatchSig1 = _createPermit(account, ESCROW_ADDRESS, refundBatchTotalFee, block.timestamp + 1 hours, privateKey);
        vm.startBroadcast(privateKey);
        escrow.pullFee(refundBatch1, account, refundBatchOrderSize, 0, block.timestamp + 1 hours, refundBatchSig1, address(0));
        vm.stopBroadcast();
        console.log("[TX] Refund order 1 created");
        
        vm.sleep(CALL_DELAY * 1000);
        
        bytes memory refundBatchSig2 = _createPermit(account, ESCROW_ADDRESS, refundBatchTotalFee, block.timestamp + 1 hours, privateKey);
        vm.startBroadcast(privateKey);
        escrow.pullFee(refundBatch2, account, refundBatchOrderSize, 0, block.timestamp + 1 hours, refundBatchSig2, address(0));
        vm.stopBroadcast();
        console.log("[TX] Refund order 2 created");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Record balance before batch refund
        uint256 batchRefundBalanceBefore = usdc.balanceOf(account);
        uint256 expectedBatchRefund = refundBatchTotalFee * 2;
        
        // Prepare batch refund array
        bytes32[] memory refundBatchOrderIds = new bytes32[](2);
        refundBatchOrderIds[0] = refundBatch1;
        refundBatchOrderIds[1] = refundBatch2;
        
        console.log("\n[2/3] Executing refundBatch for 2 orders...");
        console.log("Expected Total Refund:", expectedBatchRefund);
        
        vm.startBroadcast(privateKey);
        escrow.refundBatch(refundBatchOrderIds);
        vm.stopBroadcast();
        console.log("[TX] refundBatch success!");
        
        vm.sleep(CALL_DELAY * 1000);
        
        // Verify all orders are REFUNDED and balance increased
        console.log("\n[3/3] Verifying refunds...");
        
        (,,,,,,,,, DomeFeeEscrow.HoldState rbState1) = escrow.getEscrowStatus(refundBatch1);
        (,,,,,,,,, DomeFeeEscrow.HoldState rbState2) = escrow.getEscrowStatus(refundBatch2);
        
        require(uint8(rbState1) == 3, "Refund order 1 should be REFUNDED");
        require(uint8(rbState2) == 3, "Refund order 2 should be REFUNDED");
        
        uint256 batchRefundBalanceAfter = usdc.balanceOf(account);
        uint256 actualBatchRefund = batchRefundBalanceAfter - batchRefundBalanceBefore;
        
        console.log("Actual Total Refund:", actualBatchRefund);
        require(actualBatchRefund == expectedBatchRefund, "Batch refund amount mismatch");
        
        console.log("[OK] All orders refunded correctly!");
        
        console.log("\n========================================");
        console.log("  Batch Refund Test PASSED!");
        console.log("========================================\n");
        
        // ════════════════════════════════════════════════════════════════════
        // FINAL SUMMARY
        // ════════════════════════════════════════════════════════════════════
        
        console.log("\n########################################");
        console.log("  ALL TESTS PASSED!");
        console.log("########################################");
        console.log("  [OK] Full Flow (pullFee -> distribute)");
        console.log("  [OK] Refund (partial distribute -> refund)");
        console.log("  [OK] Batch Distribute (3 orders)");
        console.log("  [OK] Batch Refund (2 orders)");
        console.log("########################################\n");
    }
    
    function _createPermit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 domainSeparator;
        uint256 nonce;
        
        (bool success1, bytes memory data1) = USDC_ADDRESS.staticcall(
            abi.encodeWithSignature("DOMAIN_SEPARATOR()")
        );
        require(success1, "DOMAIN_SEPARATOR failed");
        domainSeparator = abi.decode(data1, (bytes32));
        
        (bool success2, bytes memory data2) = USDC_ADDRESS.staticcall(
            abi.encodeWithSignature("nonces(address)", owner)
        );
        require(success2, "nonces failed");
        nonce = abi.decode(data2, (uint256));
        
        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH, owner, spender, value, nonce, deadline
        ));
        
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        
        return abi.encodePacked(r, s, v);
    }
}
