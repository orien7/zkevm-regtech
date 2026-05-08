/**
 * Deployment Script — Polygon zkEVM RegTech Platform
 * ===================================================
 * Deploys KYCProofVerifier and KYCRegistry to Polygon zkEVM
 *
 * Networks:
 *   - zkEVM Cardona Testnet (chainId: 2442)
 *   - zkEVM Mainnet (chainId: 1101)
 *
 * Usage:
 *   npx hardhat run scripts/deploy.ts --network zkevm-testnet
 *   npx hardhat run scripts/deploy.ts --network zkevm-mainnet
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

interface DeploymentRecord {
  network:            string;
  chainId:            number;
  deployer:           string;
  deployedAt:         string;
  contracts: {
    KYCProofVerifier: string;
    KYCRegistry:      string;
  };
  txHashes: {
    KYCProofVerifier: string;
    KYCRegistry:      string;
  };
  gasUsed: {
    KYCProofVerifier: string;
    KYCRegistry:      string;
  };
}

async function main() {
  console.log("\n=== Polygon zkEVM RegTech Deployment ===\n");

  const [deployer] = await ethers.getSigners();
  const chainId    = (await ethers.provider.getNetwork()).chainId;

  console.log(`Network:  ${network.name} (chainId: ${chainId})`);
  console.log(`Deployer: ${deployer.address}`);
  console.log(`Balance:  ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} ETH\n`);

  // ── 1. Deploy ZK Verifier ──────────────────────────────────────────────────
  console.log("1. Deploying KYCProofVerifier...");
  const Verifier = await ethers.getContractFactory("KYCProofVerifier");
  const verifier = await Verifier.deploy(deployer.address);
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  const verifierReceipt = await verifier.deploymentTransaction()!.wait();

  console.log(`   ✓ KYCProofVerifier: ${verifierAddress}`);
  console.log(`     Gas used: ${verifierReceipt?.gasUsed.toString()}`);

  // ── 2. Load Verifying Key from trusted setup ceremony ─────────────────────
  const vkeyPath = path.join(__dirname, "../circuits/artifacts/verification_key.json");
  if (fs.existsSync(vkeyPath)) {
    console.log("\n2. Loading Groth16 verifying key from trusted setup...");
    const vkey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));

    const setKeyTx = await verifier.setVerifyingKey(
      vkey.vk_alpha_1.slice(0, 2),
      [vkey.vk_beta_2[0].slice(0, 2), vkey.vk_beta_2[1].slice(0, 2)],
      [vkey.vk_gamma_2[0].slice(0, 2), vkey.vk_gamma_2[1].slice(0, 2)],
      [vkey.vk_delta_2[0].slice(0, 2), vkey.vk_delta_2[1].slice(0, 2)],
      vkey.IC.map((ic: string[]) => ic.slice(0, 2))
    );
    await setKeyTx.wait();
    console.log("   ✓ Verifying key set");
  } else {
    console.log("\n2. ⚠ Verifying key not found — run trusted setup first:");
    console.log("   npx snarkjs powersoftau new bn128 20 pot20_0000.ptau -v");
    console.log("   npx snarkjs groth16 setup kyc_proof.r1cs pot20_final.ptau kyc_proof_0000.zkey");
    console.log("   npx snarkjs zkey contribute kyc_proof_0000.zkey kyc_proof_final.zkey");
    console.log("   npx snarkjs zkey export verificationkey kyc_proof_final.zkey verification_key.json");
  }

  // ── 3. Deploy KYC Registry ─────────────────────────────────────────────────
  console.log("\n3. Deploying KYCRegistry...");
  const Registry = await ethers.getContractFactory("KYCRegistry");
  const registry = await Registry.deploy(verifierAddress, deployer.address);
  await registry.waitForDeployment();
  const registryAddress = await registry.getAddress();
  const registryReceipt = await registry.deploymentTransaction()!.wait();

  console.log(`   ✓ KYCRegistry: ${registryAddress}`);
  console.log(`     Gas used: ${registryReceipt?.gasUsed.toString()}`);

  // ── 4. Post-deployment configuration ─────────────────────────────────────
  console.log("\n4. Configuring access control...");

  // Grant VERIFIER_ROLE to initial authorised CASPs
  // In production: replace with actual licensed CASP addresses after FCA registration
  const VERIFIER_ROLE  = ethers.keccak256(ethers.toUtf8Bytes("VERIFIER_ROLE"));
  const REGULATOR_ROLE = ethers.keccak256(ethers.toUtf8Bytes("REGULATOR_ROLE"));
  const AUDITOR_ROLE   = ethers.keccak256(ethers.toUtf8Bytes("AUDITOR_ROLE"));

  // Placeholder: self-grant for testnet — REPLACE with multisig on mainnet
  if (chainId !== 1101n) {
    await (await registry.grantRole(VERIFIER_ROLE, deployer.address)).wait();
    await registry.setVerifierAuthorisation(deployer.address, true);
    console.log(`   ✓ VERIFIER_ROLE granted to deployer (testnet only)`);
  } else {
    console.log("   ⚠ Mainnet: manually grant VERIFIER_ROLE to licensed CASPs via governance multisig");
  }

  // ── 5. Save deployment record ─────────────────────────────────────────────
  const record: DeploymentRecord = {
    network:    network.name,
    chainId:    Number(chainId),
    deployer:   deployer.address,
    deployedAt: new Date().toISOString(),
    contracts: {
      KYCProofVerifier: verifierAddress,
      KYCRegistry:      registryAddress,
    },
    txHashes: {
      KYCProofVerifier: verifier.deploymentTransaction()!.hash,
      KYCRegistry:      registry.deploymentTransaction()!.hash,
    },
    gasUsed: {
      KYCProofVerifier: verifierReceipt?.gasUsed.toString() || "0",
      KYCRegistry:      registryReceipt?.gasUsed.toString() || "0",
    },
  };

  const outPath = path.join(__dirname, `../config/deployment-${network.name}.json`);
  fs.writeFileSync(outPath, JSON.stringify(record, null, 2));
  console.log(`\n5. ✓ Deployment record saved to: ${outPath}`);

  // ── 6. Verify on Polygonscan ──────────────────────────────────────────────
  if (chainId === 1101n || chainId === 2442n) {
    console.log("\n6. Run to verify on Polygonscan zkEVM:");
    console.log(`   npx hardhat verify --network ${network.name} ${verifierAddress} ${deployer.address}`);
    console.log(`   npx hardhat verify --network ${network.name} ${registryAddress} ${verifierAddress} ${deployer.address}`);
  }

  console.log("\n=== Deployment Complete ===\n");
  console.log("Contract Addresses:");
  console.log(`  KYCProofVerifier : ${verifierAddress}`);
  console.log(`  KYCRegistry      : ${registryAddress}`);
  console.log("\nNext steps:");
  console.log("  1. Run trusted setup ceremony if not done");
  console.log("  2. Set verifying key on KYCProofVerifier");
  console.log("  3. Grant VERIFIER_ROLE to licensed CASP addresses");
  console.log("  4. Grant AUDITOR_ROLE to FCA/competent authority address");
  console.log("  5. Configure backend with contract addresses");
  console.log("  6. Run circuit compilation: npx circom circuits/kyc_proof.circom --r1cs --wasm");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
