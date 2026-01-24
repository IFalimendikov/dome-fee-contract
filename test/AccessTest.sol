// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DomeFeeEscrowTest} from "./DomeFeeEscrow.t.sol";
import {DomeFeeEscrow} from "../contracts/DomeFeeEscrow.sol";

/**
 * @title AccessTest
 * @notice Security and adversarial tests for DomeFeeEscrow contract
 */
contract AccessTest is DomeFeeEscrowTest {
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

    function test_Attack_UnauthorizedPullFee() public {
        address attacker = address(0xBAD);
        bytes memory sig = new bytes(65);

        vm.prank(attacker);
        vm.expectRevert();
        escrow.pullFee(ORDER_ID, userEoa, 1_000_000_000, 0, block.timestamp + 1, sig, address(0));
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
    // Additional Security Tests - Edge Cases
    // ═══════════════════════════════════════════════════════════════════════

    function test_Attack_ClientFeeTooHigh() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 orderSize = 1_000_000_000;
        uint256 invalidClientFeeBps = 10001;
        
        bytes memory sig = _createPermitSignature(userEoa, address(escrow), escrow.minDomeFee(), deadline, userPrivateKey);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.ClientFeeTooHigh.selector, invalidClientFeeBps, 10000));
        escrow.pullFee(ORDER_ID, userEoa, orderSize, invalidClientFeeBps, deadline, sig, client);
    }

    function test_Attack_ZeroPayerAddress() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = new bytes(65);

        vm.prank(operator);
        vm.expectRevert(DomeFeeEscrow.ZeroAddress.selector);
        escrow.pullFee(ORDER_ID, address(0), 1_000_000_000, 0, deadline, sig, address(0));
    }

    function test_Attack_RescueToZeroAddress() public {
        usdc.mint(address(escrow), 1_000_000);

        vm.prank(admin);
        vm.expectRevert(DomeFeeEscrow.ZeroAddress.selector);
        escrow.rescueTokens(address(usdc), address(0), 1_000_000);
    }

    function test_Attack_RescueZeroAmount() public {
        usdc.mint(address(escrow), 1_000_000);

        vm.prank(admin);
        vm.expectRevert(DomeFeeEscrow.ZeroAmount.selector);
        escrow.rescueTokens(address(usdc), admin, 0);
    }

    function test_Attack_AddZeroOperator() public {
        vm.prank(admin);
        vm.expectRevert(DomeFeeEscrow.ZeroAddress.selector);
        escrow.addOperator(address(0));
    }

    function test_Attack_InvalidSignatureLength() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory shortSig = new bytes(64);

        vm.prank(operator);
        vm.expectRevert(DomeFeeEscrow.InvalidSignatureLength.selector);
        escrow.pullFee(ORDER_ID, userEoa, 1_000_000_000, 0, deadline, shortSig, address(0));
    }

    function test_Attack_DistributeToZeroClientGoesDome() public {
        bytes32 orderId = keccak256("no-client-order");
        uint256 orderSize = 1_000_000_000;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 expectedDomeFee = (orderSize * escrow.domeFeeBps()) / 10000;
        uint256 clientFeeBps = 10;
        uint256 expectedClientFee = (orderSize * clientFeeBps) / 10000;
        uint256 totalFee = expectedDomeFee + expectedClientFee;

        bytes memory sig = _createPermitSignature(userEoa, address(escrow), totalFee, deadline, userPrivateKey);

        vm.prank(operator);
        escrow.pullFee(orderId, userEoa, orderSize, clientFeeBps, deadline, sig, address(0));

        uint256 domeWalletBefore = usdc.balanceOf(domeWallet);

        vm.prank(operator);
        escrow.distribute(orderId, expectedDomeFee, expectedClientFee);

        assertEq(usdc.balanceOf(domeWallet), domeWalletBefore + expectedDomeFee + expectedClientFee);
    }

    function test_Attack_BatchSkipsInvalidOrders() public {
        bytes32 order1 = keccak256("batch-valid");
        bytes32 order2 = keccak256("batch-invalid");

        _setupHeldOrder(order1, user, 100_000, 50_000);

        bytes32[] memory orderIds = new bytes32[](2);
        orderIds[0] = order1;
        orderIds[1] = order2;

        uint256[] memory domeAmounts = new uint256[](2);
        domeAmounts[0] = 100_000;
        domeAmounts[1] = 100_000;

        uint256[] memory clientAmounts = new uint256[](2);
        clientAmounts[0] = 50_000;
        clientAmounts[1] = 50_000;

        uint256 domeWalletBefore = usdc.balanceOf(domeWallet);

        vm.prank(operator);
        escrow.distributeBatch(orderIds, domeAmounts, clientAmounts);

        assertEq(usdc.balanceOf(domeWallet), domeWalletBefore + 100_000);
        assertEq(uint256(escrow.states(order1)), uint256(DomeFeeEscrow.HoldState.SENT));
        assertEq(uint256(escrow.states(order2)), uint256(DomeFeeEscrow.HoldState.EMPTY));
    }

    function test_Attack_BatchSkipsOverDistribution() public {
        bytes32 order1 = keccak256("batch-skip-over");
        _setupHeldOrder(order1, user, 100_000, 50_000);

        bytes32[] memory orderIds = new bytes32[](1);
        orderIds[0] = order1;

        uint256[] memory domeAmounts = new uint256[](1);
        domeAmounts[0] = 200_000;

        uint256[] memory clientAmounts = new uint256[](1);
        clientAmounts[0] = 0;

        uint256 domeWalletBefore = usdc.balanceOf(domeWallet);

        vm.prank(operator);
        escrow.distributeBatch(orderIds, domeAmounts, clientAmounts);

        assertEq(usdc.balanceOf(domeWallet), domeWalletBefore);
        assertEq(uint256(escrow.states(order1)), uint256(DomeFeeEscrow.HoldState.HELD));
    }

    function test_Attack_RefundBatchSkipsNonHeld() public {
        bytes32 order1 = keccak256("refund-batch-valid");
        bytes32 order2 = keccak256("refund-batch-invalid");

        _setupHeldOrder(order1, user, 100_000, 50_000);

        bytes32[] memory orderIds = new bytes32[](2);
        orderIds[0] = order1;
        orderIds[1] = order2;

        uint256 userBefore = usdc.balanceOf(user);

        vm.prank(operator);
        escrow.refundBatch(orderIds);

        assertEq(usdc.balanceOf(user), userBefore + 150_000);
    }

    function testFuzz_Attack_ClientFeeMaxBoundary(uint256 clientFeeBps) public {
        clientFeeBps = bound(clientFeeBps, 10001, type(uint256).max);
        
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = new bytes(65);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.ClientFeeTooHigh.selector, clientFeeBps, 10000));
        escrow.pullFee(ORDER_ID, userEoa, 1_000_000_000, clientFeeBps, deadline, sig, client);
    }

    function testFuzz_Attack_TimingBoundaryOnClaim(uint256 timestamp) public {
        bytes32 orderId = keccak256(abi.encode("timing-boundary", timestamp));
        usdc.mint(user, 200_000);
        _setupHeldOrder(orderId, user, 100_000, 100_000);

        uint256 createdAt = block.timestamp;
        
        timestamp = bound(timestamp, createdAt, createdAt + 14 days);
        vm.warp(timestamp);
        
        vm.prank(user);
        vm.expectRevert();
        escrow.claim(orderId);

        vm.warp(createdAt + 14 days + 1);
        
        vm.prank(user);
        escrow.claim(orderId);
        
        assertEq(uint256(escrow.states(orderId)), uint256(DomeFeeEscrow.HoldState.REFUNDED));
    }

    function test_Attack_ReentrancyOnDistribute() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        escrow.distribute(ORDER_ID, 100_000, 50_000);

        assertEq(uint256(escrow.states(ORDER_ID)), uint256(DomeFeeEscrow.HoldState.SENT));
    }

    function test_Attack_ClaimOnRefundedOrder() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        escrow.refund(ORDER_ID);

        vm.warp(block.timestamp + 14 days + 1);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, ORDER_ID));
        escrow.claim(ORDER_ID);
    }

    function test_Attack_ClaimOnSentOrder() public {
        _setupHeldOrder(ORDER_ID, user, 100_000, 50_000);

        vm.prank(operator);
        escrow.distribute(ORDER_ID, 100_000, 50_000);

        vm.warp(block.timestamp + 14 days + 1);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, ORDER_ID));
        escrow.claim(ORDER_ID);
    }

    function test_Attack_RefundOnEmptyOrder() public {
        bytes32 emptyOrderId = keccak256("never-created");

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, emptyOrderId));
        escrow.refund(emptyOrderId);
    }

    function test_Attack_DistributeOnEmptyOrder() public {
        bytes32 emptyOrderId = keccak256("never-created");

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, emptyOrderId));
        escrow.distribute(emptyOrderId, 100, 100);
    }

    function test_Attack_ClaimOnEmptyOrder() public {
        bytes32 emptyOrderId = keccak256("never-created");

        vm.warp(block.timestamp + 14 days + 1);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(DomeFeeEscrow.NotHeld.selector, emptyOrderId));
        escrow.claim(emptyOrderId);
    }
}
