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
- **Access Control**: `OPERATOR` (daily operations) + `ADMIN` (configuration)
- **Batch Operations**: Efficient multi-order distribution and refunds

## Fee Escrow Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FEE ESCROW LIFECYCLE                              │
└─────────────────────────────────────────────────────────────────────────────┘

   ┌──────────┐      pullFee()       ┌──────────┐
   │  EMPTY   │ ───────────────────► │   HELD   │
   └──────────┘                      └────┬─────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
                    ▼                     ▼                     ▼
           distribute()           distribute()            refund()
          (partial fill)          (full fill)           (cancelled)
                    │                     │                     │
                    ▼                     ▼                     ▼
              ┌──────────┐          ┌──────────┐          ┌──────────┐
              │   HELD   │          │   SENT   │          │ REFUNDED │
              │ (partial)│          │  (done)  │          │  (done)  │
              └──────────┘          └──────────┘          └──────────┘
```

### 1. Fee Collection (`pullFee`)
- Operator calls `pullFee()` with order details and user signature
- Fees calculated: `domeFee` (% of order + min floor) + `clientFee` (affiliate %)
- EOA wallets: Uses EIP-2612 permit for gasless approval
- Smart wallets: Uses EIP-1271 signature + prior `approve()`
- State: `EMPTY → HELD`

### 2. Fee Distribution (`distribute`)
- Called on order fills (partial or full)
- Sends proportional amounts to Dome wallet and client/affiliate
- Supports partial fills - tracks distributed vs remaining
- State: `HELD → SENT` (when fully distributed)

### 3. Fee Refund (`refund`)
- Called when order is cancelled or expires unfilled
- Returns remaining escrowed amount to original payer
- State: `HELD → REFUNDED`

### Batch Operations
- `distributeBatch()`: Process multiple order distributions efficiently
- `refundBatch()`: Refund multiple cancelled orders in one transaction

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

# Run tests with verbosity
forge test -vvv

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

### Roles

| Role | Permissions |
|------|-------------|
| `DEFAULT_ADMIN_ROLE` | Manage all roles |
| `ADMIN_ROLE` | Configuration, pause, rescue |
| `OPERATOR_ROLE` | pullFee, distribute, refund |

## Security

### Security Features
- ReentrancyGuard protection
- Pausable for emergency stops
- Role-based access control
- EIP-712 typed data signing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
