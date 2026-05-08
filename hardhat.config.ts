import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";

dotenv.config();

const DEPLOYER_PK = process.env.DEPLOYER_PRIVATE_KEY || "0x" + "0".repeat(64);
const POLYGONSCAN_API_KEY = process.env.POLYGONSCAN_API_KEY || "";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,   // Required for some complex zk verifier contracts
    },
  },

  networks: {
    // ── Polygon zkEVM Cardona Testnet ────────────────────────────────────────
    "zkevm-testnet": {
      url:      "https://rpc.cardona.zkevm-rpc.com",
      chainId:  2442,
      accounts: [DEPLOYER_PK],
      gasPrice: "auto",
    },

    // ── Polygon zkEVM Mainnet ─────────────────────────────────────────────
    "zkevm-mainnet": {
      url:      "https://zkevm-rpc.com",
      chainId:  1101,
      accounts: [DEPLOYER_PK],
      gasPrice: "auto",
    },

    // ── Local development (Hardhat node) ─────────────────────────────────
    hardhat: {
      chainId: 31337,
    },
  },

  etherscan: {
    apiKey: {
      "zkevm-mainnet": POLYGONSCAN_API_KEY,
      "zkevm-testnet": POLYGONSCAN_API_KEY,
    },
    customChains: [
      {
        network:  "zkevm-mainnet",
        chainId:  1101,
        urls: {
          apiURL:     "https://api-zkevm.polygonscan.com/api",
          browserURL: "https://zkevm.polygonscan.com",
        },
      },
      {
        network:  "zkevm-testnet",
        chainId:  2442,
        urls: {
          apiURL:     "https://api-cardona-zkevm.polygonscan.com/api",
          browserURL: "https://cardona-zkevm.polygonscan.com",
        },
      },
    ],
  },

  paths: {
    sources:   "./contracts",
    tests:     "./test",
    cache:     "./cache",
    artifacts: "./artifacts",
  },

  gasReporter: {
    enabled:  true,
    currency: "GBP",
    token:    "MATIC",
  },
};

export default config;
