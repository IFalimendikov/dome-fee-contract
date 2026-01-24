# Dome Fee Escrow

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-^0.8.24-blue.svg)](https://soliditylang.org/)

Universal trading fee escrow with dual-wallet support and user-authorized collection. Secures fees upfront, distributes proportionally on fills, and refunds on cancellation.

## Overview

```
╔════════════════════════════════════════════════════════════════════════════════╗
|    ___   ___  __  __ ___   ___          ___                        __   ___    |
|   |   \ / _ \|  \/  | __| | __|__ ___  | __|___ __ _ _ _____ __ __ \ \ / / |   |
|   | |) | (_) | |\/| | _|  | _/ -_) -_) | _|(_-</ _| '_/ _ \ V  V /  \ V /| |   |
|   |___/ \___/|_|  |_|___| |_|\___\___| |___/__/\__|_| \___/\_/\_/    \_/ |_|   |
|                                                                                |
╚════════════════════════════════════════════════════════════════════════════════╝
```

## Features

### Unified API
Single `pullFee()` works seamlessly with all wallet types:

| Wallet Type | Method | Requirements |
|------------|--------|--------------|
| **EOA Wallets** (MetaMask, Privy) | EIP-2612 permit | Gasless approval via signature |
| **Smart Contract Wallets** (Safe, Argent) | EIP-1271 | Prior `USDC.approve()` required |

### Key Features
- **State Machine**: `EMPTY → HELD → SENT/REFUNDED`
- **User Protection**: 14-day timeout escape hatch for unresponsive operator
- **Access Control**: `OPERATOR` (daily operations) + `ADMIN` (configuration)
- **Batch Operations**: Efficient multi-order distribution and refunds

## Project Structure

```
dome-fee-contract/
├── contracts/
│   └── DomeFeeEscrow.sol    # Main escrow contract
├── test/
│   └── DomeFeeEscrow.t.sol  # Foundry test suite
├── scripts/
│   └── Deploy.s.sol         # Deployment script
├── foundry.toml             # Foundry configuration
├── remappings.txt           # Import remappings
├── README.md
└── LICENSE
```

## Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) - Smart contract development toolchain

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/dome-fee-contract.git
cd dome-fee-contract

# Install dependencies
forge install OpenZeppelin/openzeppelin-contracts
forge install foundry-rs/forge-std

# Build contracts
forge build
```

### Running Tests

```bash
# Run all tests
forge test

# Run tests with verbosity
forge test -vvv

# Run specific test
forge test --match-test testDistribute

# Run tests with gas report
forge test --gas-report

# Run coverage
forge coverage
```

### Deployment

1. **Set environment variables:**
   ```bash
   export PRIVATE_KEY=your_private_key
   export RPC_URL=your_rpc_url
   export USDC_ADDRESS=0x...
   export DOME_WALLET=0x...
   ```

2. **Deploy:**
   ```bash
   # Dry run
   forge script scripts/Deploy.s.sol --rpc-url $RPC_URL

   # Deploy
   forge script scripts/Deploy.s.sol --rpc-url $RPC_URL --broadcast --verify
   ```

## Contract API

### Core Functions

#### `pullFee`
Pull fee from user - auto-detects EOA vs Smart Wallet.

```solidity
function pullFee(
    bytes32 orderId,
    address payer,
    uint256 orderSize,
    uint256 clientFeeBps,
    uint256 deadline,
    bytes calldata signature,
    address client
) external
```

#### `distribute`
Distribute fee on order fill (partial or full).

```solidity
function distribute(
    bytes32 orderId,
    uint256 domeAmount,
    uint256 clientAmount
) external
```

#### `refund`
Refund remaining fee to payer (order cancelled/expired).

```solidity
function refund(bytes32 orderId) external
```

#### `claim`
User can claim remaining refund after 14-day timeout if operator is unresponsive.

```solidity
function claim(bytes32 orderId) external
```

### Batch Operations

```solidity
function distributeBatch(
    bytes32[] calldata orderIds,
    uint256[] calldata domeAmounts,
    uint256[] calldata clientAmounts
) external

function refundBatch(bytes32[] calldata orderIds) external
```

### Admin Functions

| Function | Description |
|----------|-------------|
| `setDomeWallet(address)` | Update Dome wallet address |
| `setDomeFeeBps(uint256)` | Update Dome fee basis points |
| `setMinDomeFee(uint256)` | Update minimum Dome fee floor |
| `addOperator(address)` | Add an operator address |
| `removeOperator(address)` | Remove an operator address |
| `pause()` / `unpause()` | Emergency controls |
| `rescueTokens(...)` | Rescue stuck tokens |

### View Functions

```solidity
function getEscrowStatus(bytes32 orderId) external view returns (...)
function isClaimable(bytes32 orderId) external view returns (bool)
function isSmartWallet(address account) external view returns (bool)
function buildAuthHash(...) external view returns (bytes32)
```

## Configuration

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ESCROW_TIMEOUT` | 14 days | Time after which user can withdraw |
| `MAX_CLIENT_FEE_BPS` | 10000 | Maximum client fee (100%) |
| `DEFAULT_DOME_FEE_BPS` | 10 | Default Dome fee (0.1%) |
| `DEFAULT_MIN_DOME_FEE` | 10,000 | $0.01 with 6 decimals |

### Roles

| Role | Permissions |
|------|-------------|
| `DEFAULT_ADMIN_ROLE` | Manage all roles |
| `ADMIN_ROLE` | Configuration, pause, rescue |
| `OPERATOR_ROLE` | pullFee, distribute, refund |

## Security

### Audits
- [ ] Pending audit

### Security Features
- ReentrancyGuard protection
- Pausable for emergency stops
- Role-based access control
- EIP-712 typed data signing
- 14-day user escape hatch

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
