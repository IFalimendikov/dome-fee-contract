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
}
