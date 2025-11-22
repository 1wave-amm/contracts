# WaveSwap Contracts

This repository contains smart contracts for the WaveSwap protocol, an Aqua-based DEX implementation that enables efficient token swaps using the 1inch Aqua protocol.

## Overview

WaveSwap consists of two main components:

1. **WaveSwap** (`src/WaveSwap.sol`) - A swap application built on Aqua protocol that executes token swaps
2. **AquaAdapter** (`adapter/AquaAdapter.sol`) - An adapter contract that manages liquidity strategies and integrates with the FactorDAO vault system

## Contracts

### WaveSwap

**Location:** `src/WaveSwap.sol`

**Description:**
WaveSwap is an AquaApp that implements a constant product AMM (Automated Market Maker) for token swaps. It extends the Aqua protocol's `AquaApp` base contract and provides swap functionality with fee support.

#### Key Features

- **Exact Input Swaps**: Swap a specific amount of input tokens for output tokens
- **Exact Output Swaps**: Swap input tokens to receive a specific amount of output tokens
- **Quote Functions**: View functions to calculate swap amounts without executing transactions
- **Fee Support**: Configurable fees in basis points (BPS)
- **Reentrancy Protection**: Uses Aqua's transient lock mechanism for security
- **Automatic Pair Publishing**: Automatically calls `publishPairs()` on the maker adapter after swaps

#### Core Functions

##### `quoteExactIn(Strategy calldata strategy, bool zeroForOne, uint256 amountIn)`
Calculates the output amount for a given input amount without executing a swap.

**Parameters:**
- `strategy`: The strategy struct containing maker, tokens, fee, and salt
- `zeroForOne`: Direction of swap (true = token0 → token1, false = token1 → token0)
- `amountIn`: Input token amount

**Returns:** `uint256 amountOut` - Calculated output amount

##### `quoteExactOut(Strategy calldata strategy, bool zeroForOne, uint256 amountOut)`
Calculates the required input amount for a desired output amount.

**Parameters:**
- `strategy`: The strategy struct
- `zeroForOne`: Swap direction
- `amountOut`: Desired output amount

**Returns:** `uint256 amountIn` - Required input amount

##### `swapExactIn(...)`
Executes a swap with a fixed input amount.

**Parameters:**
- `strategy`: Strategy configuration
- `zeroForOne`: Swap direction
- `amountIn`: Input token amount
- `amountOutMin`: Minimum acceptable output (slippage protection)
- `to`: Recipient address
- `bytes calldata`: Additional data (unused)

**Returns:** `uint256 amountOut` - Actual output amount

**Process:**
1. Calculates output amount using constant product formula
2. Validates minimum output requirement
3. Pulls output tokens from maker's Aqua strategy
4. Transfers input tokens from caller
5. Pushes input tokens to maker's Aqua strategy
6. Verifies the push was successful
7. Calls `publishPairs()` on the maker adapter

##### `swapExactOut(...)`
Executes a swap with a fixed output amount.

**Parameters:**
- `strategy`: Strategy configuration
- `zeroForOne`: Swap direction
- `amountOut`: Desired output amount
- `amountInMax`: Maximum acceptable input (slippage protection)
- `to`: Recipient address
- `bytes calldata`: Additional data (unused)

**Returns:** `uint256 amountIn` - Actual input amount

#### Pricing Model

WaveSwap uses the constant product formula (x * y = k) with fee deduction:

- **Exact In**: `amountOut = (amountInWithFee * balanceOut) / (balanceIn + amountInWithFee)`
- **Exact Out**: `amountIn = (balanceIn * amountOutWithFee).ceilDiv(balanceOut - amountOutWithFee)`

Where `amountInWithFee = amountIn * (BPS_BASE - feeBps) / BPS_BASE`

#### Strategy Structure

```solidity
struct Strategy {
    address maker;      // Liquidity provider address (AquaAdapter)
    address token0;     // First token in pair
    address token1;     // Second token in pair
    uint256 feeBps;     // Fee in basis points (e.g., 30 = 0.3%)
    bytes32 salt;      // Strategy nonce/salt for uniqueness
}
```

---

### AquaAdapter

**Location:** `adapter/AquaAdapter.sol`

**Description:**
AquaAdapter is a BaseAdapter implementation that manages liquidity strategies on the Aqua protocol. It integrates with FactorDAO's vault system and handles strategy lifecycle management, pair configuration, and liquidity provisioning.

#### Key Features

- **Strategy Management**: Creates, updates, and manages Aqua strategies
- **Pair Configuration**: Manages trading pairs with configurable fees
- **Multi-DEX Support**: Supports multiple DEX addresses per pair
- **Price Feeds**: Integrates Chainlink price feeds for value calculations
- **Liquidity Provisioning**: Automatically ships strategies to Aqua protocol
- **View Function Registration**: Registers view functions for vault integration

#### Core Functions

##### `setPair(...)`
Configures a new trading pair or updates an existing one.

**Parameters:**
- `token0`: First token address
- `token1`: Second token address
- `feeBps`: Fee in basis points
- `chainlinkFeed0`: Chainlink price feed for token0
- `chainlinkFeed1`: Chainlink price feed for token1
- `dexes`: Array of DEX addresses (swap apps) for this pair

**Process:**
1. Stores Chainlink feed addresses
2. Creates or updates pair in storage
3. Activates view function selectors
4. Automatically calls `publishPairs()` to ship strategies

##### `publishPairs()`
Publishes all configured pairs to the Aqua protocol by shipping strategies.

**Process:**
- Iterates through all pairs
- For each pair, ships strategies to all configured DEXes
- Increments strategy nonce only for the first DEX per pair
- Docks existing strategies before creating new ones

##### `_shipStrategy(...)`
Internal function that creates a new Aqua strategy.

**Parameters:**
- `token0`: First token address
- `token1`: Second token address
- `feeBps`: Fee in basis points
- `dex`: DEX (swap app) address
- `shouldIncrementNonce`: Whether to increment the strategy nonce

**Process:**
1. Calculates balanced amounts based on Chainlink prices
2. Approves Aqua to transfer tokens
3. Docks existing strategy if present
4. Creates new strategy struct
5. Ships strategy to Aqua protocol
6. Stores strategy data in storage

##### `estimateOutput(...)`
Estimates the output amount for a swap based on current strategy balances.

**Parameters:**
- `token0`: First token address
- `token1`: Second token address
- `amount0`: Amount of token0 (must be 0 if amount1 > 0)
- `amount1`: Amount of token1 (must be 0 if amount0 > 0)

**Returns:** `uint256 outputAmount` - Estimated output amount

**Formula:** Uses simple ratio: `output = (input * reserveOut) / reserveIn`

#### Storage Structure

The adapter uses Diamond Storage pattern via `AquaAdapterStorage`:

- **strategies**: Maps pair hash → DEX address → StrategyData
- **strategyNonces**: Maps pair hash → nonce counter
- **pairExists**: Maps pair hash → boolean
- **chainlinkFeeds**: Maps token address → Chainlink feed address
- **pairs**: Array of Pair structs

#### Integration with WaveSwap

1. **Liquidity Provider**: AquaAdapter acts as the maker (liquidity provider) for WaveSwap
2. **Strategy Creation**: AquaAdapter creates strategies that WaveSwap can execute swaps against
3. **Pair Publishing**: After swaps, WaveSwap calls `publishPairs()` to update strategies
4. **Balance Management**: AquaAdapter manages token balances and ships them to Aqua

---

## Architecture

```
┌─────────────┐
│   Vault     │
│  (FactorDAO)│
└──────┬──────┘
       │
       │ uses
       ▼
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│AquaAdapter  │──────▶│   Aqua       │◀─────│  WaveSwap   │
│  (Maker)    │ ship  │  Protocol    │ pull │  (App)      │
└─────────────┘       └──────────────┘ push └─────────────┘
       │                      │
       │                      │
       └──────────────────────┘
              manages
              strategies
```

**Flow:**
1. AquaAdapter ships liquidity strategies to Aqua protocol
2. Users call WaveSwap to execute swaps
3. WaveSwap pulls output tokens from Aqua strategies
4. WaveSwap pushes input tokens to Aqua strategies
5. WaveSwap calls `publishPairs()` on AquaAdapter to update strategies

---

## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

- Foundry: https://book.getfoundry.sh/
- Aqua Protocol: https://github.com/1inch/aqua

## Usage

### Build

```shell
forge build
```

### Test

```shell
forge test
```

### Format

```shell
forge fmt
```

### Gas Snapshots

```shell
forge snapshot
```

### Anvil

```shell
anvil
```

### Deploy WaveSwap

**Simulate deployment:**
```shell
forge script script/DeployWaveSwap.s.sol:DeployWaveSwap --rpc-url <RPC_URL>
```

**Deploy with default Aqua address (Base network):**
```shell
forge script script/DeployWaveSwap.s.sol:DeployWaveSwap \
  --rpc-url <RPC_URL> \
  --broadcast \
  --verify
```

**Deploy with custom Aqua address:**
```shell
AQUA_ADDRESS=0xYourAquaAddress forge script script/DeployWaveSwap.s.sol:DeployWaveSwap \
  --rpc-url <RPC_URL> \
  --broadcast \
  --verify
```

### Cast

```shell
cast <subcommand>
```

### Help

```shell
forge --help
anvil --help
cast --help
```

## Dependencies

- **OpenZeppelin Contracts** (`@openzeppelin/contracts`) - For Math utilities and ERC20 interfaces
- **1inch Aqua** (`@1inch/aqua`) - Core Aqua protocol contracts
- **forge-std** - Foundry standard library

## Network Configuration

### Base Network
- **Aqua Contract**: `0x499943E74FB0cE105688beeE8Ef2ABec5D936d31`
- Deployed at block: `38281777`

## License

- WaveSwap: LicenseRef-Degensoft-Aqua-Source-1.1
- AquaAdapter: MIT
