import { Price } from '@app/services/price.service';
import { IChannel } from '@interfaces/node-api.interface';
import { ParsedTaproot } from '../shared/transaction.utils';

export interface Transaction {
  txid: string;
  version: number;
  locktime: number;
  size: number;
  weight: number;
  fee: number;
  vin: Vin[];
  vout: Vout[];
  status: Status;

  // Custom properties
  firstSeen?: number;
  feePerVsize?: number;
  effectiveFeePerVsize?: number;
  ancestors?: Ancestor[];
  descendants?: Ancestor[];
  bestDescendant?: BestDescendant | null;
  cpfpChecked?: boolean;
  acceleration?: boolean;
  acceleratedBy?: number[];
  acceleratedAt?: number;
  feeDelta?: number;
  deleteAfter?: number;
  _unblinded?: any;
  _deduced?: boolean;
  _outspends?: Outspend[];
  _channels?: TransactionChannels;
  price?: Price;
  sigops?: number;
  flags?: bigint;
  largeInput?: boolean;
  largeOutput?: boolean;
  // OPNet extension
  opnet?: OPNetTransactionExtension;
}

// OPNet Smart Contract Types
export type MLDSASecurityLevel = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
export type OPNetTransactionType = 'Generic' | 'Deployment' | 'Interaction';

export interface PostQuantumInfo {
  mldsaPublicKey: string;
  tweakedKey: string;
  legacySignatureType: 'schnorr' | 'ecdsa';
  securityLevel: 'LEVEL2' | 'LEVEL3' | 'LEVEL5';
  algorithm: MLDSASecurityLevel;
}

export interface ContractEvent {
  contractAddress: string;
  type: string;
  data?: string;
  decodedProperties?: Record<string, unknown>;
}

export interface GasInfo {
  estimatedGas?: string | number;
  gasUsed: string | number;
  specialGasUsed: string | number;
  refundedGas?: string | number;
}

export interface AccessList {
  [contractAddress: string]: {
    [storageKey: string]: string;
  };
}

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

export interface OPNetTransactionReceipt {
  receipt?: string;
  receiptProofs?: string[];
  events?: {
    [contractAddress: string]: { type: string; data: string }[];
  };
  revert?: string;
  gasUsed: string;
  specialGasUsed: string;
}

export interface OPNetFeatures {
  hasAccessList: boolean;
  hasEpochSubmission: boolean;
  hasMLDSALink: boolean;
  featureFlags: number;
}

export interface MLDSALinkInfo {
  level: 'LEVEL2' | 'LEVEL3' | 'LEVEL5';
  hashedPublicKey: string;
  fullPublicKey?: string;
  legacySignature: string;
  isVerified: boolean;
  tweakedKey?: string;
  originalKey?: string;
}

export interface EpochSubmissionInfo {
  epochNumber: string;
  minerPublicKey: string;
  solution: string;
  salt: string;
  graffiti?: string;
  graffitiHex?: string;
  signature: string;
}

export interface OPNetTransactionExtension {
  opnetType: OPNetTransactionType;
  features?: OPNetFeatures;
  deployment?: OPNetDeploymentData;
  interaction?: OPNetInteractionData;
  mldsaLink?: MLDSALinkInfo;
  epochSubmission?: EpochSubmissionInfo;
  receipt?: OPNetTransactionReceipt;
  gasInfo?: GasInfo;
  pqInfo?: PostQuantumInfo;
  events?: ContractEvent[];
  accessList?: AccessList;
}

export interface TransactionChannels {
  inputs: { [vin: number]: IChannel };
  outputs: { [vout: number]: IChannel };
}

interface Ancestor {
  txid: string;
  weight: number;
  fee: number;
}

interface BestDescendant {
  txid: string;
  weight: number;
  fee: number;
}

export interface Recent {
  txid: string;
  fee: number;
  vsize: number;
  value: number;
}

export interface Vin {
  txid: string;
  vout: number;
  is_coinbase: boolean;
  scriptsig: string;
  scriptsig_asm: string;
  inner_redeemscript_asm?: string;
  inner_witnessscript_asm?: string;
  sequence: any;
  witness?: string[];
  prevout: Vout;
  // Elements
  is_pegin?: boolean;
  issuance?: Issuance;
  // Custom
  lazy?: boolean;
  // Ord
  isInscription?: boolean;
  // temporary field for extracted raw simplicity scripts
  inner_simplicityscript?: string;
  // parsed taproot info
  taprootInfo?: ParsedTaproot;
}

interface Issuance {
  asset_id: string;
  is_reissuance: string;
  asset_blinding_nonce: string;
  asset_entropy: string;
  contract_hash: string;
  assetamount?: number;
  assetamountcommitment?: string;
  tokenamount?: number;
  tokenamountcommitment?: string;
}

export interface Vout {
  scriptpubkey: string;
  scriptpubkey_asm: string;
  scriptpubkey_type: string;
  scriptpubkey_address?: string;
  value: number;
  // Elements
  valuecommitment?: number;
  asset?: string;
  pegout?: Pegout;
  // Ord
  isRunestone?: boolean;
}

interface Pegout {
  genesis_hash: string;
  scriptpubkey: string;
  scriptpubkey_asm: string;
  scriptpubkey_address: string;
}

export interface Status {
  confirmed: boolean;
  block_height?: number;
  block_hash?: string;
  block_time?: number;
}

export interface Block {
  id: string;
  height: number;
  version: number;
  timestamp: number;
  bits: number;
  nonce: number;
  difficulty: number;
  merkle_root: string;
  tx_count: number;
  size: number;
  weight: number;
  previousblockhash: string;
  stale?: boolean;
  canonical?: string;
}

export interface Address {
  electrum?: boolean;
  address: string;
  chain_stats: ChainStats;
  mempool_stats: MempoolStats;
  is_pubkey?: boolean;
}

export interface ScriptHash {
  electrum?: boolean;
  scripthash: string;
  chain_stats: ChainStats;
  mempool_stats: MempoolStats;
}

export interface AddressOrScriptHash {
  electrum?: boolean;
  address?: string;
  scripthash?: string;
  chain_stats: ChainStats;
  mempool_stats: MempoolStats;
}

export interface AddressTxSummary {
  txid: string;
  value: number;
  height: number;
  time: number;
  price?: number;
  tx_position?: number;
}

export interface ChainStats {
  funded_txo_count: number;
  funded_txo_sum: number;
  spent_txo_count: number;
  spent_txo_sum: number;
  tx_count: number;
}

export interface MempoolStats {
  funded_txo_count: number;
  funded_txo_sum: number;
  spent_txo_count: number;
  spent_txo_sum: number;
  tx_count: number;
}

export interface Outspend {
  spent: boolean;
  txid: string;
  vin: number;
  status: Status;
}

export interface Asset {
  asset_id: string;
  issuance_txin: IssuanceTxin;
  issuance_prevout: IssuancePrevout;
  reissuance_token: string;
  contract_hash: string;
  status: Status;
  chain_stats: AssetStats;
  mempool_stats: AssetStats;
}

export interface AssetExtended extends Asset {
  name: string;
  ticker: string;
  precision: number;
  entity: Entity;
  version: number;
  issuer_pubkey: string;
}

export interface Entity {
  domain: string;
}

interface IssuanceTxin {
  txid: string;
  vin: number;
}

interface IssuancePrevout {
  txid: string;
  vout: number;
}

interface AssetStats {
  tx_count: number;
  issuance_count: number;
  issued_amount: number;
  burned_amount: number;
  has_blinded_issuances: boolean;
  reissuance_tokens: number;
  burned_reissuance_tokens: number;
  peg_in_count: number;
  peg_in_amount: number;
  peg_out_count: number;
  peg_out_amount: number;
  burn_count: number;
}

export interface Utxo {
  txid: string;
  vout: number;
  value: number;
  status: Status;
}
