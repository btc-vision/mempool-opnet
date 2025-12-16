/**
 * OPNet API Interfaces
 * Uses types from @btc-vision/transaction and opnet packages
 */

import { MLDSASecurityLevel } from '@btc-vision/transaction';
import {
  OPNetTransactionTypes,
  IDeploymentTransaction,
  IInteractionTransaction,
} from 'opnet';

// Re-export for convenience
export { MLDSASecurityLevel, OPNetTransactionTypes };

// Contract Event Structure
export interface OPNetEvent {
  contractAddress: string;
  type: string;
  data: string;
  decodedProperties?: Record<string, unknown>;
}

// Gas Breakdown
export interface OPNetGasInfo {
  estimatedGas: string;
  gasUsed: string;
  specialGasUsed: string;
  refundedGas?: string;
}

// Storage Access List
export interface OPNetAccessList {
  [contractAddress: string]: {
    [storageKey: string]: string;
  };
}

// Storage Access Entry
export interface OPNetStorageAccess {
  contractAddress: string;
  storageKey: string;
  value: string;
  accessType: 'read' | 'write';
}

// MLDSA/BIP360 Public Key Information
export interface OPNetPublicKeyInfo {
  originalPubKey?: string;
  tweakedPubkey?: string;
  p2tr?: string;
  p2op?: string;
  lowByte?: number;
  p2pkh?: string;
  p2wpkh?: string;
  mldsaHashedPublicKey?: string;
  mldsaLevel?: MLDSASecurityLevel;
  mldsaPublicKey?: string | null;
}

// Post Quantum Info (for frontend)
export interface PostQuantumInfo {
  mldsaPublicKey: string;
  tweakedKey: string;
  legacySignatureType: 'schnorr' | 'ecdsa';
  securityLevel: 'LEVEL2' | 'LEVEL3' | 'LEVEL5';
  algorithm: MLDSASecurityLevel;
}

// Contract Execution Result
export interface OPNetCallResult {
  result: string;
  events: {
    [contractAddress: string]: OPNetEvent[];
  };
  accessList: OPNetAccessList;
  revert?: string;
  estimatedGas?: string;
  specialGas?: string;
}

// Serialized Event (for JSON responses)
export interface OPNetSerializedEvent {
  type: string;
  data: string;
}

// Transaction Receipt
export interface OPNetTransactionReceipt {
  receipt?: string;
  receiptProofs?: string[];
  events?: {
    [contractAddress: string]: OPNetSerializedEvent[];
  };
  revert?: string;
  gasUsed: string;
  specialGasUsed: string;
}

// Deployment Transaction Data
export interface OPNetDeploymentData {
  contractAddress: string;
  contractPublicKey?: string;
  bytecode: string;
  bytecodeLength: number;
  deployerPubKey: string;
  deployerAddress: string;
  contractSeed?: string;
  contractSaltHash?: string;
  wasCompressed?: boolean;
}

// Interaction Transaction Data
export interface OPNetInteractionData {
  calldata?: string;
  calldataLength?: number;
  senderPubKeyHash?: string;
  contractSecret?: string;
  interactionPubKey?: string;
  contractAddress: string;
  from: string;
  wasCompressed?: boolean;
}

// OPNet Transaction Type
export type OPNetTransactionType = 'Generic' | 'Deployment' | 'Interaction';

// Enriched Transaction Response
export interface OPNetTransactionExtension {
  opnetType: OPNetTransactionType;
  deployment?: OPNetDeploymentData;
  interaction?: OPNetInteractionData;
  receipt?: OPNetTransactionReceipt;
  gasInfo?: OPNetGasInfo;
  pqInfo?: PostQuantumInfo;
  events?: OPNetEvent[];
  accessList?: OPNetAccessList;
}

// API Response types
export interface OPNetStatusResponse {
  enabled: boolean;
  connected: boolean;
  rpcUrl?: string;
  lastError?: string;
}

export interface OPNetTransactionResponse {
  txid: string;
  opnet: OPNetTransactionExtension;
}

// Raw OPNet transaction from RPC (extends opnet types)
export interface OPNetRawTransaction {
  OPNetType?: OPNetTransactionTypes;

  // Deployment fields (from IDeploymentTransaction)
  contractAddress?: string;
  contractPublicKey?: string;
  bytecode?: string;
  wasCompressed?: boolean;
  deployerPubKey?: string;
  deployerHashedPublicKey?: string;
  contractSeed?: string;
  contractSaltHash?: string;

  // Interaction fields (from IInteractionTransaction)
  calldata?: string;
  senderPubKeyHash?: string;
  contractSecret?: string;
  interactionPubKey?: string;
  from?: string;

  // Common fields
  burnedBitcoin?: string;
  priorityFee?: string;
  gasUsed?: string;
  specialGasUsed?: string;
  events?: {
    [contractAddress: string]: OPNetEvent[];
  };
  receipt?: string;
  receiptProofs?: string[];
  revert?: string;
}
