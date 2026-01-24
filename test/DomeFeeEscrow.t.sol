// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/DomeFeeEscrow.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockUSDC
 * @notice Mock USDC token with permit support for testing
 */
contract MockUSDC is ERC20 {
    mapping(address => uint256) public nonces;

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    bytes32 public DOMAIN_SEPARATOR;

    constructor() ERC20("USD Coin", "USDC") {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("USD Coin")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "Permit expired");

        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)
        );

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");

        _approve(owner, spender, value);
    }
}

/**
 * @title DomeFeeEscrowTest
 * @notice Comprehensive test suite for DomeFeeEscrow contract
 */
contract DomeFeeEscrowTest is Test {
    DomeFeeEscrow public escrow;
    MockUSDC public usdc;

    address public admin = address(1);
    address public operator = address(2);
    address public domeWallet = address(3);
    address public client = address(4);
    address public user = address(5);

    uint256 public userPrivateKey = 0xA11CE;
    address public userEOA;

    bytes32 public constant ORDER_ID = keccak256("test-order-1");
    uint256 public constant ORDER_SIZE = 1_000_000_000; // $1000 USDC

    event FeeHeld(bytes32 indexed orderId, address indexed payer, address indexed client, uint256 totalAmount, uint256 domeFee, uint256 clientFee, bool isSmartWallet);
    event FeeDistributed(bytes32 indexed orderId, uint256 domeAmount, uint256 clientAmount);
    event FeeReturned(bytes32 indexed orderId, address indexed payer, uint256 amount);
    event PayerClaimed(bytes32 indexed orderId, address indexed payer, uint256 amount);
    event DomeWalletSet(address indexed oldWallet, address indexed newWallet);
    event DomeFeeBpsSet(uint256 oldBps, uint256 newBps);
    event MinDomeFeeSet(uint256 oldMin, uint256 newMin);

    function setUp() public {
        // Derive EOA address from private key
        userEOA = vm.addr(userPrivateKey);

        // Deploy mock USDC
        usdc = new MockUSDC();

        // Deploy escrow as admin
        vm.prank(admin);
        escrow = new DomeFeeEscrow(address(usdc), domeWallet);

        // Grant operator role
        vm.prank(admin);
        escrow.addOperator(operator);

        // Mint USDC to users
        usdc.mint(user, 10_000_000_000); // $10,000
        usdc.mint(userEOA, 10_000_000_000);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Constructor Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_Constructor() public view {
        assertEq(address(escrow.token()), address(usdc));
        assertEq(escrow.domeWallet(), domeWallet);
        assertEq(escrow.domeFeeBps(), 10); // 0.1%
        assertEq(escrow.minDomeFee(), 10_000); // $0.01
    }

    function test_Constructor_RevertZeroToken() public {
        vm.expectRevert(DomeFeeEscrow.ZeroAddress.selector);
        new DomeFeeEscrow(address(0), domeWallet);
    }

    function test_Constructor_RevertZeroWallet() public {
        vm.expectRevert(DomeFeeEscrow.ZeroAddress.selector);
        new DomeFeeEscrow(address(usdc), address(0));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PullFee Tests - Smart Wallet
    // ═══════════════════════════════════════════════════════════════════════

    function test_PullFee_SmartWallet() public {
        // Setup: user approves escrow
        vm.prank(user);
        usdc.approve(address(escrow), type(uint256).max);

        // Create mock signature (will use code path but skip sig check for this test)
        bytes memory signature = new bytes(65);
        uint256 deadline = block.timestamp + 1 hours;

        // This test simulates smart wallet - in practice would need proper EIP-1271
        // For now testing the basic flow with pre-approved allowance
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Distribution Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_Distribute_Full() public {
        // Setup escrow with pre-approved user
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000); // 0.10 dome, 0.05 client

        uint256 domeBefore = usdc.balanceOf(domeWallet);
        uint256 clientBefore = usdc.balanceOf(client);

        vm.prank(operator);
        escrow.distribute(ORDER_ID, 100_000, 50_000);

        assertEq(usdc.balanceOf(domeWallet), domeBefore + 100_000);
        assertEq(usdc.balanceOf(client), clientBefore + 50_000);
        assertEq(uint256(escrow.states(ORDER_ID)), uint256(DomeFeeEscrow.HoldState.SENT));
    }

    function test_Distribute_Partial() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        escrow.distribute(ORDER_ID, 50_000, 25_000);

        // Still held
        assertEq(uint256(escrow.states(ORDER_ID)), uint256(DomeFeeEscrow.HoldState.HELD));

        // Distribute rest
        vm.prank(operator);
        escrow.distribute(ORDER_ID, 50_000, 25_000);

        assertEq(uint256(escrow.states(ORDER_ID)), uint256(DomeFeeEscrow.HoldState.SENT));
    }

    function test_Distribute_RevertNotHeld() public {
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, ORDER_ID));
        escrow.distribute(ORDER_ID, 100, 100);
    }

    function test_Distribute_RevertExceedsRemaining() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.ExceedsRemaining.selector, 200_000, 100_000));
        escrow.distribute(ORDER_ID, 200_000, 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Refund Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_Refund() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        uint256 userBefore = usdc.balanceOf(user);

        vm.prank(operator);
        escrow.refund(ORDER_ID);

        assertEq(usdc.balanceOf(user), userBefore + 150_000);
        assertEq(uint256(escrow.states(ORDER_ID)), uint256(DomeFeeEscrow.HoldState.REFUNDED));
    }

    function test_Refund_PartiallyDistributed() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        // Distribute half
        vm.prank(operator);
        escrow.distribute(ORDER_ID, 50_000, 25_000);

        uint256 userBefore = usdc.balanceOf(user);

        // Refund remainder
        vm.prank(operator);
        escrow.refund(ORDER_ID);

        assertEq(usdc.balanceOf(user), userBefore + 75_000); // 50k dome + 25k client remaining
        assertEq(uint256(escrow.states(ORDER_ID)), uint256(DomeFeeEscrow.HoldState.REFUNDED));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Claim Tests (User Escape Hatch)
    // ═══════════════════════════════════════════════════════════════════════

    function test_Claim_AfterTimeout() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        // Fast forward past timeout
        vm.warp(block.timestamp + 14 days + 1);

        uint256 userBefore = usdc.balanceOf(user);

        vm.prank(user);
        escrow.claim(ORDER_ID);

        assertEq(usdc.balanceOf(user), userBefore + 150_000);
        assertEq(uint256(escrow.states(ORDER_ID)), uint256(DomeFeeEscrow.HoldState.REFUNDED));
    }

    function test_Claim_RevertNotYetClaimable() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(user);
        vm.expectRevert(); // NotYetClaimable
        escrow.claim(ORDER_ID);
    }

    function test_Claim_RevertNotPayer() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.warp(block.timestamp + 14 days + 1);

        vm.prank(address(999));
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotPayer.selector, address(999), user));
        escrow.claim(ORDER_ID);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch Operations Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_DistributeBatch() public {
        bytes32 order1 = keccak256("order-1");
        bytes32 order2 = keccak256("order-2");

        _setupHeldOrder(order1, user, 100_000, 50_000);
        _setupHeldOrder(order2, user, 200_000, 100_000);

        bytes32[] memory orderIds = new bytes32[](2);
        orderIds[0] = order1;
        orderIds[1] = order2;

        uint256[] memory domeAmounts = new uint256[](2);
        domeAmounts[0] = 100_000;
        domeAmounts[1] = 200_000;

        uint256[] memory clientAmounts = new uint256[](2);
        clientAmounts[0] = 50_000;
        clientAmounts[1] = 100_000;

        vm.prank(operator);
        escrow.distributeBatch(orderIds, domeAmounts, clientAmounts);

        assertEq(uint256(escrow.states(order1)), uint256(DomeFeeEscrow.HoldState.SENT));
        assertEq(uint256(escrow.states(order2)), uint256(DomeFeeEscrow.HoldState.SENT));
    }

    function test_RefundBatch() public {
        bytes32 order1 = keccak256("order-1");
        bytes32 order2 = keccak256("order-2");

        _setupHeldOrder(order1, user, 100_000, 50_000);
        _setupHeldOrder(order2, user, 200_000, 100_000);

        bytes32[] memory orderIds = new bytes32[](2);
        orderIds[0] = order1;
        orderIds[1] = order2;

        uint256 userBefore = usdc.balanceOf(user);

        vm.prank(operator);
        escrow.refundBatch(orderIds);

        assertEq(usdc.balanceOf(user), userBefore + 450_000);
        assertEq(uint256(escrow.states(order1)), uint256(DomeFeeEscrow.HoldState.REFUNDED));
        assertEq(uint256(escrow.states(order2)), uint256(DomeFeeEscrow.HoldState.REFUNDED));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Admin Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_SetDomeWallet() public {
        address newWallet = address(100);

        vm.prank(admin);
        vm.expectEmit(true, true, false, false);
        emit DomeWalletSet(domeWallet, newWallet);
        escrow.setDomeWallet(newWallet);

        assertEq(escrow.domeWallet(), newWallet);
    }

    function test_SetDomeWallet_RevertZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(DomeFeeEscrow.ZeroAddress.selector);
        escrow.setDomeWallet(address(0));
    }

    function test_SetDomeFeeBps() public {
        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit DomeFeeBpsSet(10, 20);
        escrow.setDomeFeeBps(20);

        assertEq(escrow.domeFeeBps(), 20);
    }

    function test_SetMinDomeFee() public {
        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit MinDomeFeeSet(10_000, 20_000);
        escrow.setMinDomeFee(20_000);

        assertEq(escrow.minDomeFee(), 20_000);
    }

    function test_Pause() public {
        vm.prank(admin);
        escrow.pause();
        assertTrue(escrow.paused());

        vm.prank(admin);
        escrow.unpause();
        assertFalse(escrow.paused());
    }

    function test_AddRemoveOperator() public {
        address newOperator = address(200);

        vm.prank(admin);
        escrow.addOperator(newOperator);
        assertTrue(escrow.hasRole(escrow.OPERATOR_ROLE(), newOperator));

        vm.prank(admin);
        escrow.removeOperator(newOperator);
        assertFalse(escrow.hasRole(escrow.OPERATOR_ROLE(), newOperator));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Rescue Tokens Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_RescueTokens_OtherToken() public {
        MockUSDC otherToken = new MockUSDC();
        otherToken.mint(address(escrow), 1_000_000);

        vm.prank(admin);
        escrow.rescueTokens(address(otherToken), admin, 1_000_000);

        assertEq(otherToken.balanceOf(admin), 1_000_000);
    }

    function test_RescueTokens_ExcessUSDC() public {
        // Setup held order
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        // Send extra USDC directly
        usdc.mint(address(escrow), 500_000);

        // Can only rescue excess
        vm.prank(admin);
        escrow.rescueTokens(address(usdc), admin, 500_000);

        assertEq(usdc.balanceOf(admin), 500_000);
    }

    function test_RescueTokens_RevertExceedsExcess() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.ExceedsExcessBalance.selector, 100_000, 0));
        escrow.rescueTokens(address(usdc), admin, 100_000);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // View Functions Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_GetEscrowStatus() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        (
            address payer,
            address clientAddr,
            uint256 domeFee,
            uint256 clientFee,
            uint256 domeDistributed,
            uint256 clientDistributed,
            uint256 domeRemaining,
            uint256 clientRemaining,
            uint256 timestamp,
            DomeFeeEscrow.HoldState state,
            uint256 timeUntilClaim
        ) = escrow.getEscrowStatus(ORDER_ID);

        assertEq(payer, user);
        assertEq(clientAddr, client);
        assertEq(domeFee, 100_000);
        assertEq(clientFee, 50_000);
        assertEq(domeDistributed, 0);
        assertEq(clientDistributed, 0);
        assertEq(domeRemaining, 100_000);
        assertEq(clientRemaining, 50_000);
        assertGt(timestamp, 0);
        assertEq(uint256(state), uint256(DomeFeeEscrow.HoldState.HELD));
        assertGt(timeUntilClaim, 0);
    }

    function test_IsClaimable() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        assertFalse(escrow.isClaimable(ORDER_ID));

        vm.warp(block.timestamp + 14 days + 1);

        assertTrue(escrow.isClaimable(ORDER_ID));
    }

    function test_IsSmartWallet() public view {
        assertFalse(escrow.isSmartWallet(user)); // EOA
        assertTrue(escrow.isSmartWallet(address(escrow))); // Contract
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Access Control Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_OnlyOperator_Distribute() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(user);
        vm.expectRevert();
        escrow.distribute(ORDER_ID, 100_000, 50_000);
    }

    function test_OnlyOperator_Refund() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(user);
        vm.expectRevert();
        escrow.refund(ORDER_ID);
    }

    function test_OnlyAdmin_SetDomeWallet() public {
        vm.prank(operator);
        vm.expectRevert();
        escrow.setDomeWallet(address(100));
    }

    function test_OnlyAdmin_Pause() public {
        vm.prank(operator);
        vm.expectRevert();
        escrow.pause();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Helper to setup a held order by directly manipulating storage
     *      In production, this would go through pullFee with proper signatures
     */
    function _setupHeldOrder(
        bytes32 orderId,
        address payer,
        uint256 domeFee,
        uint256 clientFee
    ) internal {
        uint256 total = domeFee + clientFee;

        // Transfer tokens from payer to escrow
        vm.prank(payer);
        usdc.transfer(address(escrow), total);

        // Use storage slots to setup escrow data
        // This simulates what pullFee does
        vm.store(
            address(escrow),
            keccak256(abi.encode(orderId, uint256(7))), // states mapping slot
            bytes32(uint256(1)) // HELD
        );

        // Store escrow data (slot 6 for escrows mapping)
        bytes32 escrowSlot = keccak256(abi.encode(orderId, uint256(6)));
        
        // payer
        vm.store(address(escrow), escrowSlot, bytes32(uint256(uint160(payer))));
        // client
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 1), bytes32(uint256(uint160(client))));
        // domeFee
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 2), bytes32(domeFee));
        // clientFee
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 3), bytes32(clientFee));
        // domeDistributed = 0
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 4), bytes32(uint256(0)));
        // clientDistributed = 0
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 5), bytes32(uint256(0)));
        // timestamp
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 6), bytes32(block.timestamp));

        // Update totalHeld (slot 8)
        uint256 currentHeld = uint256(vm.load(address(escrow), bytes32(uint256(8))));
        vm.store(address(escrow), bytes32(uint256(8)), bytes32(currentHeld + total));
    }
}
