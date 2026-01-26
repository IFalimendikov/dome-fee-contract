// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    ╔════════════════════════════════════════════════════════════════════════════════╗
    |    ___   ___  __  __ ___   ___          ___                        __   ___    |
    |   |   \ / _ \|  \/  | __| | __|__ ___  | __|___ __ _ _ _____ __ __ \ \ / / |   |
    |   | |) | (_) | |\/| | _|  | _/ -_) -_) | _|(_-</ _| '_/ _ \ V  V /  \ V /| |   |
    |   |___/ \___/|_|  |_|___| |_|\___\___| |___/__/\__|_| \___/\_/\_/    \_/ |_|   |
    |                                                                                |
    ╚════════════════════════════════════════════════════════════════════════════════╝

    @title DomeFeeEscrow
    @notice Universal trading fee escrow with dual-wallet support and user-authorized collection
            Secures fees upfront, distributes proportionally on fills, refunds on cancellation

    ════════════════════════════════════════════════════════════════════════════════
    UNIFIED API
    ════════════════════════════════════════════════════════════════════════════════

         Single pullFee() works seamlessly with all wallet types:

         ┌─ EOA WALLETS (MetaMask, Privy, etc.)
         │  ✓ EIP-2612 permit for gasless approval
         │  ✓ No approve() transaction needed
         │  ✓ Direct fee collection via permit signature
         │
         └─ SMART CONTRACT WALLETS (Safe, Argent, etc.)
            ✓ EIP-1271 signature verification
            ✓ Requires prior USDC.approve() from Safe
            ✓ User signs authorization via Safe interface

    ════════════════════════════════════════════════════════════════════════════════
    KEY FEATURES
    ════════════════════════════════════════════════════════════════════════════════

         State Machine
         • EMPTY → HELD → SENT/REFUNDED

         Access Control
         • OPERATOR (daily operations) + ADMIN (configuration)

    ════════════════════════════════════════════════════════════════════════════════
*/

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract DomeFeeEscrow is 
    EIP712,
    ReentrancyGuard, 
    AccessControl, 
    Pausable 
{
    using SafeERC20 for IERC20;

    // ────────────────────────────────────────────────────────────────────────
    // Types
    // ────────────────────────────────────────────────────────────────────────

    enum HoldState { EMPTY, HELD, SENT, REFUNDED }

    // ────────────────────────────────────────────────────────────────────────
    // Events
    // ────────────────────────────────────────────────────────────────────────

    event FeeHeld(bytes32 indexed orderId, address indexed payer, address indexed client, uint256 totalAmount, uint256 domeFee, uint256 clientFee, bool isSmartWallet);
    event FeeDistributed(bytes32 indexed orderId, uint256 domeAmount, uint256 clientAmount);
    event FeeReturned(bytes32 indexed orderId, address indexed payer, uint256 amount);
    event DomeWalletSet(address indexed oldWallet, address indexed newWallet);
    event DomeFeeBpsSet(uint256 oldBps, uint256 newBps);
    event MinDomeFeeSet(uint256 oldMin, uint256 newMin);
    event TokensRescued(address indexed token, address indexed to, uint256 amount);

    // ────────────────────────────────────────────────────────────────────────
    // Errors
    // ────────────────────────────────────────────────────────────────────────

    error ZeroAddress();
    error ZeroAmount();
    error ClientFeeTooHigh(uint256 provided, uint256 maximum);
    error OrderExists(bytes32 orderId);
    error OrderNotFound(bytes32 orderId);
    error NotHeld(bytes32 orderId);
    error ArrayLengthMismatch();
    error NotPayer(address caller, address payer);
    error InvalidSignature();
    error SignatureExpired();
    error InvalidSignatureLength();
    error InsufficientAllowance(uint256 required, uint256 available);
    error ExceedsRemaining(uint256 requested, uint256 remaining);
    error ExceedsExcessBalance(uint256 requested, uint256 excess);

    // ────────────────────────────────────────────────────────────────────────
    // Storage
    // ────────────────────────────────────────────────────────────────────────
    
    /// @notice Escrow data for each order
    struct EscrowData {
        address payer;              // User/wallet that paid the fee
        address client;             // Client/affiliate to receive client fee
        uint256 domeFee;            // Total dome fee escrowed
        uint256 clientFee;          // Total client fee escrowed
        uint256 domeDistributed;    // Dome fee already sent
        uint256 clientDistributed;  // Client fee already sent
        uint256 timestamp;          // When fee was pulled
    }

    // ────────────────────────────────────────────────────────────────────────
    // Roles
    // ────────────────────────────────────────────────────────────────────────

    /// @notice Role for daily operations (pullFee, distribute, refund)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    
    /// @notice Role for configuration changes (fees, wallets, pause)
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // ────────────────────────────────────────────────────────────────────────
    // Constants
    // ────────────────────────────────────────────────────────────────────────
    
    /// @notice EIP-712 typehash for fee authorization
    /// @dev Includes payer address so user explicitly authorizes which wallet to pull from
    bytes32 public constant FEE_AUTH_TYPEHASH = keccak256(
        "FeeAuth(bytes32 orderId,address payer,uint256 amount,uint256 deadline)"
    );
    
    /// @notice Maximum client fee bps (100% = 10000 bps)
    uint256 public constant MAX_CLIENT_FEE_BPS = 10000;
    
    /// @notice Default Dome fee in basis points (0.1% = 10 bps)
    uint256 public constant DEFAULT_DOME_FEE_BPS = 10;
    
    /// @notice Default minimum Dome fee ($0.01 with 6 decimals)
    uint256 public constant DEFAULT_MIN_DOME_FEE = 10_000;

    // ────────────────────────────────────────────────────────────────────────
    // State Variables
    // ────────────────────────────────────────────────────────────────────────

    /// @notice USDC token contract (immutable)
    IERC20 public immutable TOKEN;
    
    /// @notice Dome wallet to receive Dome's share
    address public domeWallet;
    
    /// @notice Dome fee in basis points (default 0.1% = 10 bps)
    uint256 public domeFeeBps;
    
    /// @notice Minimum Dome fee floor in USDC (6 decimals)
    uint256 public minDomeFee;

    /// @notice Escrow data per order
    mapping(bytes32 => EscrowData) public escrows;
    
    /// @notice Order state tracking
    mapping(bytes32 => HoldState) public states;
    
    /// @notice Total amount currently held in escrow
    uint256 public totalHeld;

    // ────────────────────────────────────────────────────────────────────────
    // Constructor
    // ────────────────────────────────────────────────────────────────────────
    
    /**
     * @notice Initialize the escrow contract
     * @dev Sets up EIP-712 domain separator and grants all roles to deployer
     *      Deployer should transfer ADMIN_ROLE to a multi-sig after setup
     * @param tokenAddress USDC token address
     * @param _domeWallet Wallet address to receive Dome's share of fees
     */
    constructor(
        address tokenAddress,
        address _domeWallet
    ) EIP712("DomeFeeEscrow", "1") {
        if (tokenAddress == address(0)) revert ZeroAddress();
        if (_domeWallet == address(0)) revert ZeroAddress();
        
        TOKEN = IERC20(tokenAddress);
        domeWallet = _domeWallet;
        domeFeeBps = DEFAULT_DOME_FEE_BPS;
        minDomeFee = DEFAULT_MIN_DOME_FEE;
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Modifiers
    // ────────────────────────────────────────────────────────────────────────

    modifier requireHeld(bytes32 orderId) {
        _requireHeld(orderId);
        _;
    }
    
    modifier requireNew(bytes32 orderId) {
        _requireNew(orderId);
        _;
    }

    function _requireHeld(bytes32 orderId) internal view {
        if (states[orderId] != HoldState.HELD) revert NotHeld(orderId);
    }

    function _requireNew(bytes32 orderId) internal view {
        if (states[orderId] != HoldState.EMPTY) revert OrderExists(orderId);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Fee Collection
    // ────────────────────────────────────────────────────────────────────────

    /**
     * @notice Pull fee from user - auto-detects EOA vs Smart Wallet
     * @dev Single unified function for all wallet types:
     *      - EOA: signature is EIP-2612 permit (65 bytes: r,s,v)
     *      - Smart Wallet: signature is EIP-1271 compatible, requires prior approve()
     * 
     * @param orderId Unique order identifier (prevents replay)
     * @param payer Address to pull fee from
     * @param orderSize Order size in USDC (used to calculate fees)
     * @param clientFeeBps Client's fee in basis points (e.g., 50 = 0.5%)
     * @param deadline Timestamp after which signature is invalid
     * @param signature For EOA: packed permit sig (65 bytes r,s,v)
     *                  For Smart Wallet: EIP-1271 compatible signature
     * @param client Address to receive client fee (can be zero for Dome-only)
     */
    function pullFee(
        bytes32 orderId,
        address payer,
        uint256 orderSize,
        uint256 clientFeeBps,
        uint256 deadline,
        bytes calldata signature,
        address client
    ) 
        external 
        onlyRole(OPERATOR_ROLE) 
        whenNotPaused 
        nonReentrant
        requireNew(orderId)
    {
        if (payer == address(0)) revert ZeroAddress();
        if (block.timestamp > deadline) revert SignatureExpired();
        if (clientFeeBps > MAX_CLIENT_FEE_BPS) revert ClientFeeTooHigh(clientFeeBps, MAX_CLIENT_FEE_BPS);
        
        // Calculate dome fee (% of order size, with minimum floor)
        uint256 domeFee = (orderSize * domeFeeBps) / 10000;
        if (domeFee < minDomeFee) {
            domeFee = minDomeFee;
        }
        
        // Calculate client fee (% of order size)
        uint256 clientFee = (orderSize * clientFeeBps) / 10000;
        
        uint256 totalAmount = domeFee + clientFee;
        if (totalAmount == 0) revert ZeroAmount();

        bool isContract = payer.code.length > 0;

        if (isContract) {
            // Smart Wallet: verify EIP-1271 signature + use existing allowance
            _handleSmartWallet(orderId, payer, totalAmount, deadline, signature);
        } else {
            // EOA: use EIP-2612 permit (gasless)
            _handleEoa(payer, totalAmount, deadline, signature);
        }

        // Store escrow data
        escrows[orderId] = EscrowData({
            payer: payer,
            client: client,
            domeFee: domeFee,
            clientFee: clientFee,
            domeDistributed: 0,
            clientDistributed: 0,
            timestamp: block.timestamp
        });
        states[orderId] = HoldState.HELD;
        totalHeld += totalAmount;

        // Transfer tokens from payer to escrow
        TOKEN.safeTransferFrom(payer, address(this), totalAmount);
        
        emit FeeHeld(orderId, payer, client, totalAmount, domeFee, clientFee, isContract);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Distribution
    // ────────────────────────────────────────────────────────────────────────

    /**
     * @notice Distribute fee on order fill (partial or full)
     * @param orderId Order identifier
     * @param domeAmount Amount to send to Dome (USDC, 6 decimals)
     * @param clientAmount Amount to send to client (USDC, 6 decimals)
     */
    function distribute(
        bytes32 orderId,
        uint256 domeAmount,
        uint256 clientAmount
    ) 
        external 
        onlyRole(OPERATOR_ROLE) 
        nonReentrant 
        whenNotPaused
        requireHeld(orderId)
    {
        EscrowData storage data = escrows[orderId];
        
        // Validate amounts don't exceed remaining
        uint256 domeRemaining = data.domeFee - data.domeDistributed;
        uint256 clientRemaining = data.clientFee - data.clientDistributed;
        
        if (domeAmount > domeRemaining) revert ExceedsRemaining(domeAmount, domeRemaining);
        if (clientAmount > clientRemaining) revert ExceedsRemaining(clientAmount, clientRemaining);
        
        // Update distributed amounts
        data.domeDistributed += domeAmount;
        data.clientDistributed += clientAmount;
        
        uint256 totalDistributed = domeAmount + clientAmount;
        totalHeld -= totalDistributed;
        
        // Mark as SENT if fully distributed
        if (data.domeDistributed == data.domeFee && data.clientDistributed == data.clientFee) {
            states[orderId] = HoldState.SENT;
        }

        // Transfer to Dome
        if (domeAmount > 0) {
            TOKEN.safeTransfer(domeWallet, domeAmount);
        }

        // Transfer to client (or Dome if no client)
        if (clientAmount > 0) {
            if (data.client != address(0)) {
                TOKEN.safeTransfer(data.client, clientAmount);
            } else {
                TOKEN.safeTransfer(domeWallet, clientAmount);
            }
        }

        emit FeeDistributed(orderId, domeAmount, clientAmount);
    }

    /**
     * @notice Refund remaining fee to payer (order cancelled/expired)
     * @param orderId Order identifier
     */
    function refund(bytes32 orderId) 
        external 
        onlyRole(OPERATOR_ROLE) 
        nonReentrant 
        whenNotPaused
        requireHeld(orderId)
    {
        EscrowData storage data = escrows[orderId];
        
        // Calculate remaining amounts
        uint256 domeRemaining = data.domeFee - data.domeDistributed;
        uint256 clientRemaining = data.clientFee - data.clientDistributed;
        uint256 totalRemaining = domeRemaining + clientRemaining;
        
        states[orderId] = HoldState.REFUNDED;
        totalHeld -= totalRemaining;
        
        if (totalRemaining > 0) {
            TOKEN.safeTransfer(data.payer, totalRemaining);
        }
        
        emit FeeReturned(orderId, data.payer, totalRemaining);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Distribution - Batch Operations
    // ────────────────────────────────────────────────────────────────────────

    /**
     * @notice Batch distribute multiple orders
     * @param orderIds Array of order identifiers
     * @param domeAmounts Array of dome amounts to distribute
     * @param clientAmounts Array of client amounts to distribute
     */
    function distributeBatch(
        bytes32[] calldata orderIds,
        uint256[] calldata domeAmounts,
        uint256[] calldata clientAmounts
    )
        external
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
    {
        if (orderIds.length != domeAmounts.length || orderIds.length != clientAmounts.length) {
            revert ArrayLengthMismatch();
        }
        
        for (uint256 i = 0; i < orderIds.length; i++) {
            bytes32 orderId = orderIds[i];
            uint256 domeAmount = domeAmounts[i];
            uint256 clientAmount = clientAmounts[i];
            
            if (states[orderId] != HoldState.HELD) continue;
            
            EscrowData storage data = escrows[orderId];
            
            // Skip if amounts exceed remaining
            uint256 domeRemaining = data.domeFee - data.domeDistributed;
            uint256 clientRemaining = data.clientFee - data.clientDistributed;
            if (domeAmount > domeRemaining || clientAmount > clientRemaining) continue;
            
            // Update distributed amounts
            data.domeDistributed += domeAmount;
            data.clientDistributed += clientAmount;
            
            uint256 totalDistributed = domeAmount + clientAmount;
            totalHeld -= totalDistributed;
            
            // Mark as SENT if fully distributed
            if (data.domeDistributed == data.domeFee && data.clientDistributed == data.clientFee) {
                states[orderId] = HoldState.SENT;
            }

            if (domeAmount > 0) {
                TOKEN.safeTransfer(domeWallet, domeAmount);
            }

            if (clientAmount > 0) {
                if (data.client != address(0)) {
                    TOKEN.safeTransfer(data.client, clientAmount);
                } else {
                    TOKEN.safeTransfer(domeWallet, clientAmount);
                }
            }

            emit FeeDistributed(orderId, domeAmount, clientAmount);
        }
    }

    /**
     * @notice Batch refund multiple orders (refunds remaining amounts)
     * @param orderIds Array of order identifiers
     */
    function refundBatch(bytes32[] calldata orderIds)
        external
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
    {
        for (uint256 i = 0; i < orderIds.length; i++) {
            bytes32 orderId = orderIds[i];
            
            if (states[orderId] != HoldState.HELD) continue;
            
            EscrowData storage data = escrows[orderId];
            
            uint256 domeRemaining = data.domeFee - data.domeDistributed;
            uint256 clientRemaining = data.clientFee - data.clientDistributed;
            uint256 totalRemaining = domeRemaining + clientRemaining;
            
            states[orderId] = HoldState.REFUNDED;
            totalHeld -= totalRemaining;
            
            if (totalRemaining > 0) {
                TOKEN.safeTransfer(data.payer, totalRemaining);
            }
            
            emit FeeReturned(orderId, data.payer, totalRemaining);
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Admin - Configuration
    // ────────────────────────────────────────────────────────────────────────

    /**
     * @notice Update Dome wallet address
     */
    function setDomeWallet(address newWallet) external onlyRole(ADMIN_ROLE) {
        if (newWallet == address(0)) revert ZeroAddress();
        
        address oldWallet = domeWallet;
        domeWallet = newWallet;
        
        emit DomeWalletSet(oldWallet, newWallet);
    }
    
    /**
     * @notice Update Dome fee basis points
     * @param newFeeBps New fee in basis points
     */
    function setDomeFeeBps(uint256 newFeeBps) external onlyRole(ADMIN_ROLE) {
        uint256 oldBps = domeFeeBps;
        domeFeeBps = newFeeBps;
        
        emit DomeFeeBpsSet(oldBps, newFeeBps);
    }
    
    /**
     * @notice Update minimum Dome fee floor
     * @param newMinFee New minimum fee in USDC (6 decimals)
     */
    function setMinDomeFee(uint256 newMinFee) external onlyRole(ADMIN_ROLE) {
        uint256 oldMin = minDomeFee;
        minDomeFee = newMinFee;
        
        emit MinDomeFeeSet(oldMin, newMinFee);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Admin - Emergency Controls
    // ────────────────────────────────────────────────────────────────────────

    /**
     * @notice Pause contract in emergency
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause contract
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Rescue stuck or accidentally sent tokens
     * @dev For USDC: only allows withdrawing excess above totalHeld
     *      For other tokens: allows full withdrawal
     * @param tokenAddress Token to rescue (can be USDC or any ERC20)
     * @param to Address to send rescued tokens to
     * @param amount Amount to rescue
     */
    function rescueTokens(
        address tokenAddress,
        address to,
        uint256 amount
    ) external onlyRole(ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        
        IERC20 rescueToken = IERC20(tokenAddress);
        
        if (tokenAddress == address(TOKEN)) {
            // For USDC: only allow withdrawing excess above totalHeld
            uint256 balance = TOKEN.balanceOf(address(this));
            uint256 excess = balance > totalHeld ? balance - totalHeld : 0;
            if (amount > excess) revert ExceedsExcessBalance(amount, excess);
        }
        
        rescueToken.safeTransfer(to, amount);
        
        emit TokensRescued(tokenAddress, to, amount);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Admin - Access Control
    // ────────────────────────────────────────────────────────────────────────

    /**
     * @notice Add an operator address
     * @param operator Address to grant OPERATOR_ROLE
     */
    function addOperator(address operator) external onlyRole(ADMIN_ROLE) {
        if (operator == address(0)) revert ZeroAddress();
        _grantRole(OPERATOR_ROLE, operator);
    }

    /**
     * @notice Remove an operator address
     * @param operator Address to revoke OPERATOR_ROLE from
     */
    function removeOperator(address operator) external onlyRole(ADMIN_ROLE) {
        _revokeRole(OPERATOR_ROLE, operator);
    }

    // ────────────────────────────────────────────────────────────────────────
    // View Functions
    // ────────────────────────────────────────────────────────────────────────

    /**
     * @notice Get escrow status for an order
     */
    function getEscrowStatus(bytes32 orderId) external view returns (
        address payer,
        address client,
        uint256 domeFee,
        uint256 clientFee,
        uint256 domeDistributed,
        uint256 clientDistributed,
        uint256 domeRemaining,
        uint256 clientRemaining,
        uint256 timestamp,
        HoldState state
    ) {
        EscrowData storage data = escrows[orderId];
        payer = data.payer;
        client = data.client;
        domeFee = data.domeFee;
        clientFee = data.clientFee;
        domeDistributed = data.domeDistributed;
        clientDistributed = data.clientDistributed;
        domeRemaining = data.domeFee - data.domeDistributed;
        clientRemaining = data.clientFee - data.clientDistributed;
        timestamp = data.timestamp;
        state = states[orderId];
    }

    /**
     * @notice Calculate fees for given order size
     * @param orderSize Order size in USDC (6 decimals)
     * @param clientFeeBps Client fee rate in basis points
     * @return domeFee Calculated dome fee (with minDomeFee floor applied)
     * @return clientFee Calculated client fee
     * @return totalFee Total fee (dome + client)
     */
    function calculateFee(
        uint256 orderSize,
        uint256 clientFeeBps
    ) external view returns (uint256 domeFee, uint256 clientFee, uint256 totalFee) {
        domeFee = (orderSize * domeFeeBps) / 10000;
        if (domeFee < minDomeFee) {
            domeFee = minDomeFee;
        }
        clientFee = (orderSize * clientFeeBps) / 10000;
        totalFee = domeFee + clientFee;
    }

    /**
     * @notice Get EIP-712 domain separator
     */
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }


    // ────────────────────────────────────────────────────────────────────────
    // Internal Helpers
    // ────────────────────────────────────────────────────────────────────────

    /**
     * @dev Handle EOA wallet using EIP-2612 permit
     */
    function _handleEoa(
        address payer,
        uint256 amount,
        uint256 deadline,
        bytes calldata signature
    ) internal {
        (uint8 v, bytes32 r, bytes32 s) = _splitSignature(signature);
        
        IERC20Permit(address(TOKEN)).permit(
            payer,
            address(this),
            amount,
            deadline,
            v, r, s
        );
    }

    /**
     * @dev Handle Smart Wallet using EIP-1271 signature verification
     */
    function _handleSmartWallet(
        bytes32 orderId,
        address payer,
        uint256 amount,
        uint256 deadline,
        bytes calldata signature
    ) internal view {
        // Build EIP-712 hash for fee authorization
        bytes32 structHash = keccak256(abi.encode(
            FEE_AUTH_TYPEHASH,
            orderId,
            payer,
            amount,
            deadline
        ));
        bytes32 hash = _hashTypedDataV4(structHash);

        // Verify via EIP-1271 (Safe's isValidSignature)
        if (!SignatureChecker.isValidSignatureNow(payer, hash, signature)) {
            revert InvalidSignature();
        }

        // Verify allowance exists (Safe must have called approve() beforehand)
        uint256 allowance = TOKEN.allowance(payer, address(this));
        if (allowance < amount) {
            revert InsufficientAllowance(amount, allowance);
        }
    }

    /**
     * @dev Split packed signature into v, r, s components
     */
    function _splitSignature(bytes calldata sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        if (sig.length != 65) revert InvalidSignatureLength();
        
        r = bytes32(sig[0:32]);
        s = bytes32(sig[32:64]);
        v = uint8(sig[64]);
        
        if (v < 27) v += 27;
    }
}
