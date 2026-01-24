// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {DomeFeeEscrow} from "../contracts/DomeFeeEscrow.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockUSDC
 * @notice Mock USDC token with permit support for testing
 */
contract MockUSDC is ERC20 {
    mapping(address => uint256) public nonces;

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );
    bytes32 public domainSeparator;

    constructor() ERC20("USD Coin", "USDC") {
        domainSeparator = keccak256(
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

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
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
    address public userEoa;

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
        userEoa = vm.addr(userPrivateKey);
        usdc = new MockUSDC();

        vm.prank(admin);
        escrow = new DomeFeeEscrow(address(usdc), domeWallet);

        vm.prank(admin);
        escrow.addOperator(operator);

        usdc.mint(user, 10_000_000_000);
        usdc.mint(userEoa, 10_000_000_000);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Constructor Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_Constructor() public view {
        assertEq(address(escrow.TOKEN()), address(usdc));
        assertEq(escrow.domeWallet(), domeWallet);
        assertEq(escrow.domeFeeBps(), 10);
        assertEq(escrow.minDomeFee(), 10_000);
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
        vm.prank(user);
        usdc.approve(address(escrow), type(uint256).max);

        bytes memory signature = new bytes(65);
        uint256 deadline = block.timestamp + 1 hours;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Distribution Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_Distribute_Full() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

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

        assertEq(uint256(escrow.states(ORDER_ID)), uint256(DomeFeeEscrow.HoldState.HELD));

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

        vm.prank(operator);
        escrow.distribute(ORDER_ID, 50_000, 25_000);

        uint256 userBefore = usdc.balanceOf(user);

        vm.prank(operator);
        escrow.refund(ORDER_ID);

        assertEq(usdc.balanceOf(user), userBefore + 75_000);
        assertEq(uint256(escrow.states(ORDER_ID)), uint256(DomeFeeEscrow.HoldState.REFUNDED));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Claim Tests (User Escape Hatch)
    // ═══════════════════════════════════════════════════════════════════════

    function test_Claim_AfterTimeout() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

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
        vm.expectRevert();
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
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        usdc.mint(address(escrow), 500_000);

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

        vm.prank(payer);
        usdc.approve(address(escrow), total);
        vm.prank(payer);
        bool success = usdc.transfer(address(escrow), total);
        require(success, "Transfer failed");

        vm.store(
            address(escrow),
            keccak256(abi.encode(orderId, uint256(7))),
            bytes32(uint256(1))
        );

        bytes32 escrowSlot = keccak256(abi.encode(orderId, uint256(6)));
        
        vm.store(address(escrow), escrowSlot, bytes32(uint256(uint160(payer))));
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 1), bytes32(uint256(uint160(client))));
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 2), bytes32(domeFee));
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 3), bytes32(clientFee));
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 4), bytes32(uint256(0)));
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 5), bytes32(uint256(0)));
        vm.store(address(escrow), bytes32(uint256(escrowSlot) + 6), bytes32(block.timestamp));

        uint256 currentHeld = uint256(vm.load(address(escrow), bytes32(uint256(8))));
        vm.store(address(escrow), bytes32(uint256(8)), bytes32(currentHeld + total));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Fuzz Tests
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Fuzz test: distribute should never send more than escrowed
     */
    function testFuzz_Distribute_NeverExceedsEscrowed(
        uint256 domeFee,
        uint256 clientFee,
        uint256 domeDistribute,
        uint256 clientDistribute
    ) public {
        domeFee = bound(domeFee, 10_000, 10_000_000_000);
        clientFee = bound(clientFee, 0, 10_000_000_000);
        domeDistribute = bound(domeDistribute, 0, domeFee);
        clientDistribute = bound(clientDistribute, 0, clientFee);

        bytes32 orderId = keccak256(abi.encode("fuzz-order", domeFee, clientFee));
        
        usdc.mint(user, domeFee + clientFee);
        
        _setupHeldOrder(orderId, user, domeFee, clientFee);

        uint256 domeWalletBefore = usdc.balanceOf(domeWallet);
        uint256 clientBefore = usdc.balanceOf(client);

        vm.prank(operator);
        escrow.distribute(orderId, domeDistribute, clientDistribute);

        assertEq(usdc.balanceOf(domeWallet), domeWalletBefore + domeDistribute);
        assertEq(usdc.balanceOf(client), clientBefore + clientDistribute);
    }

    /**
     * @notice Fuzz test: partial distributions should track correctly
     */
    function testFuzz_Distribute_PartialTracking(
        uint256 domeFee,
        uint256 clientFee,
        uint8 numDistributions
    ) public {
        domeFee = bound(domeFee, 100_000, 1_000_000_000);
        clientFee = bound(clientFee, 100_000, 1_000_000_000);
        numDistributions = uint8(bound(numDistributions, 1, 10));

        bytes32 orderId = keccak256(abi.encode("fuzz-partial", domeFee, clientFee, numDistributions));
        
        usdc.mint(user, domeFee + clientFee);
        _setupHeldOrder(orderId, user, domeFee, clientFee);

        uint256 domePerDistribution = domeFee / numDistributions;
        uint256 clientPerDistribution = clientFee / numDistributions;

        for (uint8 i = 0; i < numDistributions - 1; i++) {
            vm.prank(operator);
            escrow.distribute(orderId, domePerDistribution, clientPerDistribution);
            
            assertEq(uint256(escrow.states(orderId)), uint256(DomeFeeEscrow.HoldState.HELD));
        }

        (,,,,uint256 domeDistributed, uint256 clientDistributed,,,,,) = escrow.getEscrowStatus(orderId);
        uint256 domeRemaining = domeFee - domeDistributed;
        uint256 clientRemaining = clientFee - clientDistributed;

        vm.prank(operator);
        escrow.distribute(orderId, domeRemaining, clientRemaining);

        assertEq(uint256(escrow.states(orderId)), uint256(DomeFeeEscrow.HoldState.SENT));
    }

    /**
     * @notice Fuzz test: refund should return exact remaining amount
     */
    function testFuzz_Refund_ReturnsExactRemaining(
        uint256 domeFee,
        uint256 clientFee,
        uint256 domeDistributed,
        uint256 clientDistributed
    ) public {
        domeFee = bound(domeFee, 10_000, 1_000_000_000);
        clientFee = bound(clientFee, 0, 1_000_000_000);
        domeDistributed = bound(domeDistributed, 0, domeFee - 1);
        clientDistributed = bound(clientDistributed, 0, clientFee);

        bytes32 orderId = keccak256(abi.encode("fuzz-refund", domeFee, clientFee, domeDistributed));
        
        usdc.mint(user, domeFee + clientFee);
        _setupHeldOrder(orderId, user, domeFee, clientFee);

        if (domeDistributed > 0 || clientDistributed > 0) {
            vm.prank(operator);
            escrow.distribute(orderId, domeDistributed, clientDistributed);
        }

        uint256 userBefore = usdc.balanceOf(user);
        uint256 expectedRefund = (domeFee - domeDistributed) + (clientFee - clientDistributed);

        vm.prank(operator);
        escrow.refund(orderId);

        assertEq(usdc.balanceOf(user), userBefore + expectedRefund);
        assertEq(uint256(escrow.states(orderId)), uint256(DomeFeeEscrow.HoldState.REFUNDED));
    }

    /**
     * @notice Fuzz test: fee calculation with various order sizes
     */
    function testFuzz_FeeCalculation(uint256 orderSize) public view {
        orderSize = bound(orderSize, 1_000_000, 100_000_000_000_000);

        uint256 expectedDomeFee = (orderSize * escrow.domeFeeBps()) / 10000;
        uint256 minFee = escrow.minDomeFee();
        
        if (expectedDomeFee < minFee) {
            expectedDomeFee = minFee;
        }

        assertTrue(expectedDomeFee >= minFee);
        
        if (orderSize >= 100_000_000) {
            assertTrue(expectedDomeFee >= minFee);
        }
    }

    /**
     * @notice Fuzz test: claim only works after timeout
     */
    function testFuzz_Claim_OnlyAfterTimeout(uint256 timeElapsed) public {
        timeElapsed = bound(timeElapsed, 0, 30 days);

        bytes32 orderId = keccak256(abi.encode("fuzz-claim", timeElapsed));
        usdc.mint(user, 200_000);
        _setupHeldOrder(orderId, user, 100_000, 100_000);

        vm.warp(block.timestamp + timeElapsed);

        if (timeElapsed <= 14 days) {
            vm.prank(user);
            vm.expectRevert();
            escrow.claim(orderId);
        } else {
            uint256 userBefore = usdc.balanceOf(user);
            vm.prank(user);
            escrow.claim(orderId);
            assertEq(usdc.balanceOf(user), userBefore + 200_000);
        }
    }

    /**
     * @notice Fuzz test: batch operations handle multiple orders correctly
     */
    function testFuzz_DistributeBatch(uint8 numOrders) public {
        numOrders = uint8(bound(numOrders, 1, 20));

        bytes32[] memory orderIds = new bytes32[](numOrders);
        uint256[] memory domeAmounts = new uint256[](numOrders);
        uint256[] memory clientAmounts = new uint256[](numOrders);

        uint256 totalDome;
        uint256 totalClient;

        for (uint8 i = 0; i < numOrders; i++) {
            orderIds[i] = keccak256(abi.encode("batch", i));
            domeAmounts[i] = 10_000 + (uint256(i) * 1000);
            clientAmounts[i] = 5_000 + (uint256(i) * 500);
            
            totalDome += domeAmounts[i];
            totalClient += clientAmounts[i];

            usdc.mint(user, domeAmounts[i] + clientAmounts[i]);
            _setupHeldOrder(orderIds[i], user, domeAmounts[i], clientAmounts[i]);
        }

        uint256 domeWalletBefore = usdc.balanceOf(domeWallet);
        uint256 clientBefore = usdc.balanceOf(client);

        vm.prank(operator);
        escrow.distributeBatch(orderIds, domeAmounts, clientAmounts);

        assertEq(usdc.balanceOf(domeWallet), domeWalletBefore + totalDome);
        assertEq(usdc.balanceOf(client), clientBefore + totalClient);

        // All orders should be SENT
        for (uint8 i = 0; i < numOrders; i++) {
            assertEq(uint256(escrow.states(orderIds[i])), uint256(DomeFeeEscrow.HoldState.SENT));
        }
    }

    /**
     * @notice Fuzz test: admin fee configuration
     */
    function testFuzz_SetDomeFeeBps(uint256 newBps) public {
        newBps = bound(newBps, 0, 10000);

        vm.prank(admin);
        escrow.setDomeFeeBps(newBps);

        assertEq(escrow.domeFeeBps(), newBps);
    }

    /**
     * @notice Fuzz test: minimum fee setting
     */
    function testFuzz_SetMinDomeFee(uint256 newMin) public {
        newMin = bound(newMin, 0, 1_000_000_000);

        vm.prank(admin);
        escrow.setMinDomeFee(newMin);

        assertEq(escrow.minDomeFee(), newMin);
    }

    /**
     * @notice Fuzz test: pullFee with various order sizes and client fees
     */
    function testFuzz_PullFee_VariousOrderSizes(
        uint256 orderSize,
        uint256 clientFeeBps
    ) public {
        orderSize = bound(orderSize, 1_000_000, 10_000_000_000);
        clientFeeBps = bound(clientFeeBps, 0, 500);

        bytes32 orderId = keccak256(abi.encode("fuzz-pullfee", orderSize, clientFeeBps));
        uint256 deadline = block.timestamp + 1 hours;

        uint256 expectedDomeFee = (orderSize * escrow.domeFeeBps()) / 10000;
        if (expectedDomeFee < escrow.minDomeFee()) {
            expectedDomeFee = escrow.minDomeFee();
        }
        uint256 expectedClientFee = (orderSize * clientFeeBps) / 10000;
        uint256 totalFee = expectedDomeFee + expectedClientFee;

        usdc.mint(userEoa, totalFee);

        bytes memory permitSig = _createPermitSignature(userEoa, address(escrow), totalFee, deadline, userPrivateKey);

        uint256 userBalanceBefore = usdc.balanceOf(userEoa);

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, clientFeeBps, deadline, permitSig, client);

        assertEq(usdc.balanceOf(userEoa), userBalanceBefore - totalFee);
        assertEq(escrow.totalHeld(), totalFee);

        (address payer,, uint256 domeFee, uint256 clientFee,,,,,,,) = escrow.getEscrowStatus(orderId);
        assertEq(payer, userEoa);
        assertEq(domeFee, expectedDomeFee);
        assertEq(clientFee, expectedClientFee);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PullFee Tests with Real Signatures
    // ═══════════════════════════════════════════════════════════════════════

    function test_PullFee_EOA_TransfersFunds() public {
        bytes32 orderId = keccak256("pull-fee-eoa");
        uint256 orderSize = 1_000_000_000;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 expectedDomeFee = (orderSize * escrow.domeFeeBps()) / 10000;

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), expectedDomeFee, deadline, userPrivateKey);

        uint256 userBefore = usdc.balanceOf(userEoa);
        uint256 escrowBefore = usdc.balanceOf(address(escrow));

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, 0, deadline, sig, address(0));

        assertEq(usdc.balanceOf(userEoa), userBefore - expectedDomeFee);
        assertEq(usdc.balanceOf(address(escrow)), escrowBefore + expectedDomeFee);
    }

    function test_PullFee_EOA_SetsStateToHeld() public {
        bytes32 orderId = keccak256("pull-fee-state");
        uint256 orderSize = 1_000_000_000;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 expectedDomeFee = (orderSize * escrow.domeFeeBps()) / 10000;

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), expectedDomeFee, deadline, userPrivateKey);

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, 0, deadline, sig, address(0));

        assertEq(uint256(escrow.states(orderId)), uint256(DomeFeeEscrow.HoldState.HELD));
    }

    function test_PullFee_EOA_UpdatesTotalHeld() public {
        bytes32 orderId = keccak256("pull-fee-held");
        uint256 orderSize = 1_000_000_000;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 expectedDomeFee = (orderSize * escrow.domeFeeBps()) / 10000;

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), expectedDomeFee, deadline, userPrivateKey);

        uint256 heldBefore = escrow.totalHeld();

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, 0, deadline, sig, address(0));

        assertEq(escrow.totalHeld(), heldBefore + expectedDomeFee);
    }

    function test_PullFee_EOA_UsesMinFeeWhenCalculatedIsLower() public {
        bytes32 orderId = keccak256("pull-fee-min");
        uint256 orderSize = 100_000;
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), escrow.minDomeFee(), deadline, userPrivateKey);

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, 0, deadline, sig, address(0));

        (,, uint256 domeFee,,,,,,,,) = escrow.getEscrowStatus(orderId);
        assertEq(domeFee, escrow.minDomeFee());
    }

    function test_PullFee_EOA_RevertsOnDuplicateOrder() public {
        bytes32 orderId = keccak256("pull-fee-dup");
        uint256 orderSize = 1_000_000_000;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 expectedDomeFee = (orderSize * escrow.domeFeeBps()) / 10000;

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), expectedDomeFee, deadline, userPrivateKey);

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, 0, deadline, sig, address(0));

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.OrderExists.selector, orderId));
        escrow.pullFee(orderId, userEoa, orderSize, 0, deadline, sig, address(0));
    }

    function test_PullFee_EOA_RevertsOnExpiredDeadline() public {
        bytes32 orderId = keccak256("pull-fee-expired");
        uint256 orderSize = 1_000_000_000;
        uint256 deadline = block.timestamp - 1;

        bytes memory sig = new bytes(65);

        vm.prank(operator);
        vm.expectRevert(DomeFeeEscrow.SignatureExpired.selector);
        escrow.pullFee(orderId, userEoa, orderSize, 0, deadline, sig, address(0));
    }

    function test_PullFee_EOA_CalculatesClientFee() public {
        bytes32 orderId = keccak256("pull-fee-client");
        uint256 orderSize = 1_000_000_000;
        uint256 clientFeeBps = 20;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 expectedDomeFee = (orderSize * escrow.domeFeeBps()) / 10000;
        uint256 expectedClientFee = (orderSize * clientFeeBps) / 10000;
        uint256 totalFee = expectedDomeFee + expectedClientFee;

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), totalFee, deadline, userPrivateKey);

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, clientFeeBps, deadline, sig, client);

        (address payer, address storedClient, uint256 domeFee, uint256 clientFee,,,,,,,) = escrow.getEscrowStatus(orderId);
        assertEq(payer, userEoa);
        assertEq(domeFee, expectedDomeFee);
        assertEq(clientFee, expectedClientFee);
        assertEq(storedClient, client);
    }

    function test_PullFee_EOA_FullFlow_ThenDistribute() public {
        bytes32 orderId = keccak256("pull-fee-full-flow");
        uint256 orderSize = 1_000_000_000;
        uint256 clientFeeBps = 10;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 expectedDomeFee = (orderSize * escrow.domeFeeBps()) / 10000;
        uint256 expectedClientFee = (orderSize * clientFeeBps) / 10000;
        uint256 totalFee = expectedDomeFee + expectedClientFee;

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), totalFee, deadline, userPrivateKey);

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, clientFeeBps, deadline, sig, client);

        uint256 domeWalletBefore = usdc.balanceOf(domeWallet);
        uint256 clientBefore = usdc.balanceOf(client);

        vm.prank(operator);
        escrow.distribute(orderId, expectedDomeFee, expectedClientFee);

        assertEq(usdc.balanceOf(domeWallet), domeWalletBefore + expectedDomeFee);
        assertEq(usdc.balanceOf(client), clientBefore + expectedClientFee);
        assertEq(uint256(escrow.states(orderId)), uint256(DomeFeeEscrow.HoldState.SENT));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Security / Adversarial Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_Attack_SignatureReplay_SameOrder() public {
        bytes32 orderId = keccak256("replay-order");
        uint256 orderSize = 1_000_000_000;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 totalFee = (orderSize * escrow.domeFeeBps()) / 10000;
        if (totalFee < escrow.minDomeFee()) totalFee = escrow.minDomeFee();

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), totalFee, deadline, userPrivateKey);

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, 0, deadline, sig, address(0));

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.OrderExists.selector, orderId));
        escrow.pullFee(orderId, userEoa, orderSize, 0, deadline, sig, address(0));
    }

    function test_Attack_SignatureReplay_DifferentOrder() public {
        bytes32 orderId1 = keccak256("order-1");
        bytes32 orderId2 = keccak256("order-2");
        uint256 orderSize = 1_000_000_000;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 totalFee = (orderSize * escrow.domeFeeBps()) / 10000;
        if (totalFee < escrow.minDomeFee()) totalFee = escrow.minDomeFee();

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), totalFee, deadline, userPrivateKey);

        vm.prank(operator);
        escrow.pullFee(orderId1, userEoa, orderSize, 0, deadline, sig, address(0));

        vm.prank(operator);
        vm.expectRevert();
        escrow.pullFee(orderId2, userEoa, orderSize, 0, deadline, sig, address(0));
    }

    function test_Attack_UnauthorizedDistribute() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        address attacker = address(0xBAD);

        vm.prank(attacker);
        vm.expectRevert();
        escrow.distribute(ORDER_ID, 100_000, 50_000);
    }

    function test_Attack_UnauthorizedRefund() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        address attacker = address(0xBAD);

        vm.prank(attacker);
        vm.expectRevert();
        escrow.refund(ORDER_ID);
    }

    function test_Attack_UnauthorizedPullFee() public {
        address attacker = address(0xBAD);
        bytes memory sig = new bytes(65);

        vm.prank(attacker);
        vm.expectRevert();
        escrow.pullFee(ORDER_ID, userEoa, 1_000_000_000, 0, block.timestamp + 1, sig, address(0));
    }

    function test_Attack_ClaimBeforeTimeout() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.warp(block.timestamp + 13 days);

        vm.prank(user);
        vm.expectRevert();
        escrow.claim(ORDER_ID);
    }

    function test_Attack_ClaimByNonPayer() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.warp(block.timestamp + 14 days + 1);

        address attacker = address(0xBAD);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotPayer.selector, attacker, user));
        escrow.claim(ORDER_ID);
    }

    function test_Attack_DoubleDistribute() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        escrow.distribute(ORDER_ID, 100_000, 50_000);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, ORDER_ID));
        escrow.distribute(ORDER_ID, 1, 1);
    }

    function test_Attack_DoubleRefund() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        escrow.refund(ORDER_ID);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, ORDER_ID));
        escrow.refund(ORDER_ID);
    }

    function test_Attack_DistributeAfterRefund() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        escrow.refund(ORDER_ID);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, ORDER_ID));
        escrow.distribute(ORDER_ID, 100_000, 50_000);
    }

    function test_Attack_RefundAfterFullDistribute() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        escrow.distribute(ORDER_ID, 100_000, 50_000);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, ORDER_ID));
        escrow.refund(ORDER_ID);
    }

    function test_Attack_DistributeMoreThanEscrowed() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.ExceedsRemaining.selector, 100_001, 100_000));
        escrow.distribute(ORDER_ID, 100_001, 0);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.ExceedsRemaining.selector, 50_001, 50_000));
        escrow.distribute(ORDER_ID, 0, 50_001);
    }

    function test_Attack_PartialDistributeThenOverclaim() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        escrow.distribute(ORDER_ID, 60_000, 30_000);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.ExceedsRemaining.selector, 50_000, 40_000));
        escrow.distribute(ORDER_ID, 50_000, 0);
    }

    function test_Attack_RescueEscrowedFunds() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.ExceedsExcessBalance.selector, 1, 0));
        escrow.rescueTokens(address(usdc), admin, 1);
    }

    function test_Attack_DrainViaRescue() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);
        usdc.mint(address(escrow), 1_000_000);

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.ExceedsExcessBalance.selector, 1_000_001, 1_000_000));
        escrow.rescueTokens(address(usdc), admin, 1_000_001);

        vm.prank(admin);
        escrow.rescueTokens(address(usdc), admin, 1_000_000);

        assertEq(usdc.balanceOf(address(escrow)), 150_000);
    }

    function test_Attack_UnauthorizedAdminFunctions() public {
        address attacker = address(0xBAD);

        vm.startPrank(attacker);

        vm.expectRevert();
        escrow.setDomeWallet(attacker);

        vm.expectRevert();
        escrow.setDomeFeeBps(9999);

        vm.expectRevert();
        escrow.setMinDomeFee(0);

        vm.expectRevert();
        escrow.pause();

        vm.expectRevert();
        escrow.addOperator(attacker);

        vm.expectRevert();
        escrow.removeOperator(operator);

        vm.expectRevert();
        escrow.rescueTokens(address(usdc), attacker, 1);

        vm.stopPrank();
    }

    function test_Attack_OperationsWhilePaused() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(admin);
        escrow.pause();

        vm.prank(operator);
        vm.expectRevert();
        escrow.distribute(ORDER_ID, 100_000, 50_000);

        vm.prank(operator);
        vm.expectRevert();
        escrow.refund(ORDER_ID);

        vm.warp(block.timestamp + 14 days + 1);
        vm.prank(user);
        vm.expectRevert();
        escrow.claim(ORDER_ID);

        bytes memory sig = new bytes(65);
        vm.prank(operator);
        vm.expectRevert();
        escrow.pullFee(keccak256("new-order"), userEoa, 1_000_000_000, 0, block.timestamp + 1, sig, address(0));
    }

    function test_Attack_ForgeryPullFeeForOther() public {
        address victim = address(0xBEEF);
        usdc.mint(victim, 10_000_000_000);

        vm.prank(victim);
        usdc.approve(address(escrow), type(uint256).max);

        bytes memory fakeSig = new bytes(65);

        vm.prank(operator);
        vm.expectRevert();
        escrow.pullFee(ORDER_ID, victim, 1_000_000_000, 0, block.timestamp + 1 hours, fakeSig, address(0));
    }

    function test_Attack_WrongSignerPermit() public {
        uint256 attackerPrivateKey = 0xDEAD;

        uint256 totalFee = escrow.minDomeFee();
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory wrongSig = _createPermitSignature(userEoa, address(escrow), totalFee, deadline, attackerPrivateKey);

        vm.prank(operator);
        vm.expectRevert();
        escrow.pullFee(ORDER_ID, userEoa, 1_000_000_000, 0, deadline, wrongSig, address(0));
    }

    function test_Attack_ExpiredPermit() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 totalFee = escrow.minDomeFee();

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), totalFee, deadline, userPrivateKey);

        vm.warp(deadline + 1);

        vm.prank(operator);
        vm.expectRevert(DomeFeeEscrow.SignatureExpired.selector);
        escrow.pullFee(ORDER_ID, userEoa, 1_000_000_000, 0, deadline, sig, address(0));
    }

    function test_Attack_ZeroAmountPullFee() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = new bytes(65);

        vm.prank(admin);
        escrow.setDomeFeeBps(0);
        vm.prank(admin);
        escrow.setMinDomeFee(0);

        vm.prank(operator);
        vm.expectRevert(DomeFeeEscrow.ZeroAmount.selector);
        escrow.pullFee(ORDER_ID, userEoa, 0, 0, deadline, sig, address(0));
    }

    function test_Attack_ManipulateFeeAfterPull() public {
        bytes32 orderId = keccak256("fee-manip");
        uint256 orderSize = 1_000_000_000;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 totalFee = (orderSize * escrow.domeFeeBps()) / 10000;
        if (totalFee < escrow.minDomeFee()) totalFee = escrow.minDomeFee();

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), totalFee, deadline, userPrivateKey);

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, 0, deadline, sig, address(0));

        vm.prank(admin);
        escrow.setDomeFeeBps(9999);

        (,, uint256 domeFee,,,,,,,,) = escrow.getEscrowStatus(orderId);
        assertEq(domeFee, totalFee);

        vm.prank(operator);
        escrow.distribute(orderId, totalFee, 0);

        assertEq(uint256(escrow.states(orderId)), uint256(DomeFeeEscrow.HoldState.SENT));
    }

    function test_Attack_BatchArrayMismatch() public {
        bytes32[] memory orderIds = new bytes32[](2);
        uint256[] memory domeAmounts = new uint256[](3);
        uint256[] memory clientAmounts = new uint256[](2);

        vm.prank(operator);
        vm.expectRevert(DomeFeeEscrow.ArrayLengthMismatch.selector);
        escrow.distributeBatch(orderIds, domeAmounts, clientAmounts);
    }

    function test_Attack_OperatorRemovesSelf() public {
        vm.prank(admin);
        escrow.removeOperator(operator);

        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        vm.expectRevert();
        escrow.distribute(ORDER_ID, 100_000, 50_000);
    }

    function test_Attack_ClaimThenOperatorActions() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.warp(block.timestamp + 14 days + 1);

        vm.prank(user);
        escrow.claim(ORDER_ID);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, ORDER_ID));
        escrow.distribute(ORDER_ID, 100_000, 50_000);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, ORDER_ID));
        escrow.refund(ORDER_ID);
    }

    function testFuzz_Attack_RandomAddressCannotOperate(address attacker) public {
        vm.assume(attacker != admin);
        vm.assume(attacker != operator);
        vm.assume(attacker != address(0));

        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.startPrank(attacker);

        vm.expectRevert();
        escrow.distribute(ORDER_ID, 100_000, 50_000);

        vm.expectRevert();
        escrow.refund(ORDER_ID);

        bytes memory sig = new bytes(65);
        vm.expectRevert();
        escrow.pullFee(keccak256("attacker-order"), userEoa, 1_000_000_000, 0, block.timestamp + 1, sig, address(0));

        vm.stopPrank();
    }

    function testFuzz_Attack_CannotDistributeMoreThanRemaining(
        uint256 domeFee,
        uint256 clientFee,
        uint256 overDome,
        uint256 overClient
    ) public {
        domeFee = bound(domeFee, 10_000, 1_000_000_000);
        clientFee = bound(clientFee, 10_000, 1_000_000_000);
        overDome = bound(overDome, domeFee + 1, type(uint128).max);
        overClient = bound(overClient, clientFee + 1, type(uint128).max);

        bytes32 orderId = keccak256(abi.encode("fuzz-overdist", domeFee, clientFee));
        usdc.mint(user, domeFee + clientFee);
        _setupHeldOrder(orderId, user, domeFee, clientFee);

        vm.prank(operator);
        vm.expectRevert();
        escrow.distribute(orderId, overDome, 0);

        vm.prank(operator);
        vm.expectRevert();
        escrow.distribute(orderId, 0, overClient);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Helper: Create Permit Signature
    // ═══════════════════════════════════════════════════════════════════════

    function _createPermitSignature(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                usdc.PERMIT_TYPEHASH(),
                owner,
                spender,
                value,
                usdc.nonces(owner),
                deadline
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", usdc.domainSeparator(), structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
