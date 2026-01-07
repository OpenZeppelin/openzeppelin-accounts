# Deployment Scripts

This directory contains Foundry scripts for deploying the OpenAccountFramework contracts to multiple blockchain networks.

The `OpenAccountFactory` is deployed using the [Arachnid deterministic deployment proxy](https://github.com/Arachnid/deterministic-deployment-proxy) at address `0x4e59b44847b379578588920cA78FbF26c0B4956C`. This approach ensures the factory has the same address across all EVM-compatible chains, making it easier for users and developers to interact with the system consistently.

According to [this research](https://ethereum-magicians.org/t/eip-7997-deterministic-factory-predeploy/24998/15), the Arachnid deployment proxy is the most widely adopted proxy available, and its prevalence suggests it as an effective approach for deterministic addresses across chains. This is further supported by proposals like [RIP-7740](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7740.md).

## Usage

### Prerequisites

1. **Foundry Installation**: Ensure you have Foundry installed
2. **Wallet Setup**: Configure your deployer wallet using Cast keystore:
   ```bash
   cast wallet import <ACCOUNT_NAME> --interactive
   ```
3. **API Keys**: Obtain Etherscan API keys for contract verification (optional but recommended)

Make sure to fund your deployer wallet on the chain you're deploying in.

### Testing Deployment (Dry Run)

Test the deployment script without broadcasting transactions:

```bash
# From the packages/contracts/ directory
forge script ./scripts/deployments/OpenAccountFactory.s.sol:OpenAccountFactoryScript --rpc-url <RPC_NAME>
```

Replace `<RPC_NAME>` with any of the supported networks (see [Supported Networks](#supported-networks)).

**Example:**

```bash
forge script ./scripts/deployments/OpenAccountFactory.s.sol:OpenAccountFactoryScript --rpc-url sepolia
```

### Production Deployment

Deploy and verify the factory on a live network:

```bash
ETHERSCAN_API_KEY=<API_KEY> \
ETH_FROM=$(cast wallet address --account <ACCOUNT_NAME>) \
forge script ./scripts/deployments/OpenAccountFactory.s.sol:OpenAccountFactoryScript \
  --rpc-url <RPC_NAME> \
  --account <ACCOUNT_NAME> \
  --verify \
  --broadcast
```

**Parameters:**

- `ETHERSCAN_API_KEY`: Your Etherscan (or equivalent) API key for contract verification
- `ETH_FROM`: The deployer address (automatically extracted from your keystore)
- `--account`: The name of your Cast keystore account
- `--verify`: Enable contract verification on block explorer
- `--broadcast`: Actually send the transactions (omit for simulation)

**Example:**

```bash
ETHERSCAN_API_KEY=<API_KEY> \
ETH_FROM=$(cast wallet address --account deployer) \
forge script ./scripts/deployments/OpenAccountFactory.s.sol:OpenAccountFactoryScript \
  --rpc-url base_sepolia \
  --account deployer \
  --verify \
  --broadcast
```

### Verifying Existing Deployments

If a contract was deployed but not verified, you can verify it separately:

```bash
forge verify-contract \
  --rpc-url <RPC_NAME> \
  <CONTRACT_ADDRESS> \
  src/OpenAccountFactory.sol:OpenAccountFactory \
  --etherscan-api-key <API_KEY>
```

### Advanced Options

For chains with custom block explorers, specify the verifier URL:

```bash
forge script ./scripts/deployments/OpenAccountFactory.s.sol:OpenAccountFactoryScript \
  --rpc-url <RPC_NAME> \
  --broadcast \
  --verify \
  --verifier-url https://explorer.example.com/api
```

## Adding New Networks

To deploy to a new network:

1. **Add RPC endpoint** to `foundry.toml`:

   ```toml
   [rpc_endpoints]
   my_network = "https://rpc.my-network.com"
   ```

2. **Run the deployment script** with the new network name:

   ```bash
   forge script ./scripts/deployments/OpenAccountFactory.s.sol:OpenAccountFactoryScript --rpc-url my_network --broadcast
   ```

3. **Update this README** with the new network in the [Supported Networks](#supported-networks) section

## Deployment Records

Deployment addresses are stored in `deployments.json` at the repository root, structured by chain ID:

```json
{
  "1": {
    "OpenAccountFactory": "0x..."
  },
  "11155111": {
    "OpenAccountFactory": "0x..."
  }
}
```

The script automatically updates this file after each deployment.

## Supported Networks

The following networks have RPC endpoints configured in `foundry.toml`:

### Mainnets

- `mainnet`: Ethereum Mainnet
- `arbitrum`: Arbitrum One
- `avalanche`: Avalanche C-Chain
- `base`: Base
- `bnb_smart_chain`: BNB Smart Chain
- `optimism`: Optimism
- `polygon`: Polygon PoS
- `zksync`: zkSync Era

### Testnets

- `sepolia`: Ethereum Sepolia
- `arbitrum_sepolia`: Arbitrum Sepolia
- `avalanche_fuji`: Avalanche Fuji
- `base_sepolia`: Base Sepolia
- `bnb_smart_chain_testnet`: BNB Smart Chain Testnet
- `optimism_sepolia`: Optimism Sepolia
- `polygon_amoy`: Polygon Amoy
- `zksync_sepolia`: zkSync Era Sepolia
