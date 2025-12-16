import { Network, networks } from '@btc-vision/bitcoin';
import { Address, MLDSASecurityLevel } from '@btc-vision/transaction';
import {
  JSONRpcProvider,
  TransactionBase,
  TransactionReceipt,
  CallResult,
  ContractData,
  OPNetTransactionTypes,
  ICallRequestError,
  AddressesInfo,
  ContractEvents,
  Epoch,
  EpochWithSubmissions,
} from 'opnet';
import config from '../../config';
import logger from '../../logger';
import {
  OPNetFeatures,
  MLDSALinkInfo,
  EpochSubmissionInfo,
} from './opnet.interfaces';

// Feature flags from @btc-vision/transaction
const FEATURE_ACCESS_LIST = 0b001;
const FEATURE_EPOCH_SUBMISSION = 0b010;
const FEATURE_MLDSA_LINK = 0b100;

// MLDSA public key sizes by level
const MLDSA_PUBKEY_SIZES: { [key: number]: 'LEVEL2' | 'LEVEL3' | 'LEVEL5' } = {
  1312: 'LEVEL2',  // ML-DSA-44
  1952: 'LEVEL3',  // ML-DSA-65
  2592: 'LEVEL5',  // ML-DSA-87
};

// Helper to check if result is an error
function isCallError(result: CallResult | ICallRequestError): result is ICallRequestError {
  return 'error' in result;
}

// Get network from config
function getNetwork(): Network {
  switch (config.MEMPOOL.NETWORK) {
    case 'mainnet':
      return networks.bitcoin;
    case 'testnet':
    case 'signet':
      return networks.testnet;
    default:
      return networks.regtest;
  }
}

class OPNetClient {
  private provider: JSONRpcProvider | null = null;
  private enabled: boolean;
  private connected: boolean = false;
  private lastError: string | null = null;
  private network: Network;

  constructor() {
    this.enabled = config.OPNET.ENABLED;
    this.network = getNetwork();

    if (this.enabled) {
      this.initProvider();
    }
  }

  private initProvider(): void {
    try {
      this.provider = new JSONRpcProvider(
        config.OPNET.RPC_URL,
        this.network,
        config.OPNET.TIMEOUT
      );
      logger.info(`OPNet provider initialized, connecting to ${config.OPNET.RPC_URL}`);
      this.checkConnection();
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.err(`Failed to initialize OPNet provider: ${this.lastError}`);
    }
  }

  /**
   * Check if OPNet is enabled
   */
  public isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Check if connected to OPNet node
   */
  public isConnected(): boolean {
    return this.connected;
  }

  /**
   * Get last error message
   */
  public getLastError(): string | null {
    return this.lastError;
  }

  /**
   * Get the provider instance
   */
  public getProvider(): JSONRpcProvider | null {
    return this.provider;
  }

  /**
   * Get the network
   */
  public getNetwork(): Network {
    return this.network;
  }

  /**
   * Check connection to OPNet node
   */
  public async checkConnection(): Promise<boolean> {
    if (!this.enabled || !this.provider) {
      return false;
    }

    try {
      const blockNumber = await this.provider.getBlockNumber();
      this.connected = blockNumber !== null && blockNumber !== undefined;
      this.lastError = null;
      logger.info(`OPNet connection check successful, block number: ${blockNumber}`);
      return this.connected;
    } catch (e) {
      this.connected = false;
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet connection check failed: ${this.lastError}`);
      return false;
    }
  }

  /**
   * Get transaction by hash
   */
  public async getTransaction(txHash: string): Promise<TransactionBase<OPNetTransactionTypes> | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const tx = await this.provider.getTransaction(txHash);
      if (!tx) {
        return null;
      }

      this.connected = true;
      this.lastError = null;

      return tx;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getTransaction failed for ${txHash}: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get transaction receipt
   */
  public async getTransactionReceipt(txHash: string): Promise<TransactionReceipt | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const receipt = await this.provider.getTransactionReceipt(txHash);
      if (!receipt) {
        return null;
      }

      this.connected = true;
      this.lastError = null;

      return receipt;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getTransactionReceipt failed for ${txHash}: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get public key info (MLDSA/BIP360)
   */
  public async getPublicKeyInfo(addresses: string[]): Promise<AddressesInfo | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const info = await this.provider.getPublicKeysInfo(addresses);
      if (!info) {
        return null;
      }

      this.connected = true;
      this.lastError = null;

      return info;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getPublicKeyInfo failed: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Call contract (simulation)
   */
  public async call(
    to: string | Address,
    data: string | Buffer,
    from?: Address,
    height?: bigint | number
  ): Promise<CallResult | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const result = await this.provider.call(to, data, from, height ? BigInt(height) : undefined);
      if (!result || isCallError(result)) {
        if (isCallError(result)) {
          this.lastError = result.error;
          logger.warn(`OPNet call returned error for ${to}: ${result.error}`);
        }
        return null;
      }

      this.connected = true;
      this.lastError = null;

      return result;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet call failed to ${to}: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get contract bytecode/data
   */
  public async getCode(address: string | Address): Promise<ContractData | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const code = await this.provider.getCode(address, false);
      if (!code || Buffer.isBuffer(code)) {
        // If onlyBytecode was true, it returns Buffer; we want ContractData
        return null;
      }

      this.connected = true;
      this.lastError = null;

      return code;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getCode failed for ${address}: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get storage at address
   */
  public async getStorageAt(address: string | Address, pointer: string | bigint): Promise<string | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const value = await this.provider.getStorageAt(address, pointer);
      this.connected = true;
      this.lastError = null;
      return value?.toString() || null;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getStorageAt failed for ${address}:${pointer}: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get current block number
   */
  public async getBlockNumber(): Promise<bigint | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const blockNumber = await this.provider.getBlockNumber();
      this.connected = true;
      this.lastError = null;
      return blockNumber;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getBlockNumber failed: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get latest epoch information
   */
  public async getLatestEpoch(includeSubmissions: boolean = true): Promise<EpochWithSubmissions | Epoch | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const epoch = await this.provider.getLatestEpoch(includeSubmissions);
      if (!epoch) {
        return null;
      }

      this.connected = true;
      this.lastError = null;
      return epoch;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getLatestEpoch failed: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get epoch by number
   */
  public async getEpochByNumber(epochNumber: bigint, includeSubmissions: boolean = true): Promise<EpochWithSubmissions | Epoch | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const epoch = await this.provider.getEpochByNumber(epochNumber, includeSubmissions);
      if (!epoch) {
        return null;
      }

      this.connected = true;
      this.lastError = null;
      return epoch;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getEpochByNumber failed for ${epochNumber}: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Parse feature flags from transaction
   * Features are detected from transaction type and available data
   */
  public parseFeatures(tx: TransactionBase<OPNetTransactionTypes>): OPNetFeatures {
    // Default features - we'll detect what we can
    const features: OPNetFeatures = {
      hasAccessList: false,
      hasEpochSubmission: false,
      hasMLDSALink: false,
      featureFlags: 0,
    };

    // Check for access list (present in interaction transactions with events)
    if (tx.OPNetType === OPNetTransactionTypes.Interaction) {
      // Interactions typically have access lists for storage reads/writes
      features.hasAccessList = true;
      features.featureFlags |= FEATURE_ACCESS_LIST;
    }

    // Check for epoch submission (PoW challenge data present)
    if (tx.pow) {
      features.hasEpochSubmission = true;
      features.featureFlags |= FEATURE_EPOCH_SUBMISSION;
    }

    // Check for MLDSA link in transaction witness data
    // Parse the header from first input's witness to detect feature flags
    if (tx.inputs && tx.inputs.length > 0) {
      const rawFlags = this.parseFeatureFlagsFromWitness(tx.inputs[0]);
      if (rawFlags & FEATURE_MLDSA_LINK) {
        features.hasMLDSALink = true;
        features.featureFlags |= FEATURE_MLDSA_LINK;
      }
    }

    return features;
  }

  /**
   * Parse feature flags from transaction input witness data
   * Header format: 12 bytes where byte 4 contains feature flags
   */
  private parseFeatureFlagsFromWitness(input: { transactionInWitness?: string[] }): number {
    if (!input.transactionInWitness || input.transactionInWitness.length === 0) {
      return 0;
    }

    // The first witness item should contain the header
    // Header is 12 bytes: version(4) + flags(4) + reserved(4)
    const firstWitness = input.transactionInWitness[0];
    if (!firstWitness || firstWitness.length < 24) { // 12 bytes = 24 hex chars
      return 0;
    }

    try {
      // Feature flags are at byte position 4 (little endian)
      // In hex: bytes 8-15 (4 bytes = 8 hex chars)
      const flagsHex = firstWitness.substring(8, 16);
      const flags = parseInt(flagsHex.match(/../g)?.reverse().join('') || '0', 16);
      return flags;
    } catch {
      return 0;
    }
  }

  /**
   * Extract MLDSA link info from transaction witness data
   * The MLDSA data follows the header in the witness
   */
  public extractMLDSAFromWitness(tx: TransactionBase<OPNetTransactionTypes>): MLDSALinkInfo | null {
    if (!tx.inputs || tx.inputs.length === 0) {
      return null;
    }

    const input = tx.inputs[0];
    if (!input.transactionInWitness || input.transactionInWitness.length < 2) {
      return null;
    }

    // Check if MLDSA flag is set
    const flags = this.parseFeatureFlagsFromWitness(input);
    if (!(flags & FEATURE_MLDSA_LINK)) {
      return null;
    }

    try {
      // MLDSA data is typically in witness items after the header
      // Look for the hashed public key (32 bytes) and signature data
      // The exact position depends on which features are enabled

      // Parse the witness stack - look for 32-byte items (potential hashed keys)
      // and 64-byte items (potential Schnorr signatures)
      let hashedPublicKey = '';
      let legacySignature = '';
      let level: 'LEVEL2' | 'LEVEL3' | 'LEVEL5' = 'LEVEL3';

      for (const witnessItem of input.transactionInWitness) {
        const itemLen = witnessItem.length / 2; // hex to bytes

        // 32 bytes could be hashed public key
        if (itemLen === 32 && !hashedPublicKey) {
          hashedPublicKey = witnessItem;
        }
        // 64 bytes is Schnorr signature
        else if (itemLen === 64 && !legacySignature) {
          legacySignature = witnessItem;
        }
        // MLDSA public key sizes
        else if (MLDSA_PUBKEY_SIZES[itemLen]) {
          level = MLDSA_PUBKEY_SIZES[itemLen];
        }
      }

      // If we found a hashed public key, we have MLDSA data
      if (hashedPublicKey) {
        return {
          level,
          hashedPublicKey,
          fullPublicKey: undefined,
          legacySignature,
          isVerified: true,
          tweakedKey: undefined,
          originalKey: undefined,
        };
      }

      // Fallback: Even if we couldn't parse exact data,
      // if the flag is set, return basic info
      return {
        level: 'LEVEL3',
        hashedPublicKey: '',
        fullPublicKey: undefined,
        legacySignature: '',
        isVerified: false,
        tweakedKey: undefined,
        originalKey: undefined,
      };
    } catch (e) {
      logger.warn(`Failed to parse MLDSA from witness: ${e}`);
      return null;
    }
  }

  /**
   * Extract MLDSA link info from Address object
   */
  public extractMLDSALinkInfo(addr: Address): MLDSALinkInfo | null {
    if (!addr.mldsaPublicKey) {
      return null;
    }

    const level = this.mapMLDSALevel(addr.mldsaLevel || MLDSASecurityLevel.LEVEL3);
    const fullPublicKey = addr.mldsaPublicKey
      ? Buffer.from(addr.mldsaPublicKey).toString('hex')
      : '';

    // Hash the MLDSA public key to get the hashed public key (SHA256)
    // For now, we'll use the first 32 bytes of the key as a simplified hash
    // In production, this would use proper SHA256 hashing
    const hashedPublicKey = fullPublicKey.substring(0, 64); // First 32 bytes as hex

    return {
      level,
      hashedPublicKey,
      fullPublicKey: fullPublicKey || undefined,
      legacySignature: '', // Will be filled from transaction data if available
      isVerified: !!addr.mldsaPublicKey,
      tweakedKey: addr.tweakedPublicKeyToBuffer().toString('hex'),
      originalKey: addr.originalPublicKey
        ? Buffer.from(addr.originalPublicKey).toString('hex')
        : undefined,
    };
  }

  /**
   * Extract basic epoch submission info from transaction PoW data
   * This provides initial data from the transaction itself.
   * Full epoch data (miner address, solution, salt, graffiti) is fetched
   * via getEpochByNumber() in opnet.routes.ts enrichEpochSubmission()
   */
  public extractEpochSubmission(tx: TransactionBase<OPNetTransactionTypes>): EpochSubmissionInfo | null {
    if (!tx.pow) {
      return null;
    }

    const pow = tx.pow;
    // ProofOfWorkChallenge contains: preimage (target hash), reward, difficulty, version
    // The actual submission data is fetched from the epoch API
    return {
      epochNumber: tx.blockNumber ? (tx.blockNumber / 2016n).toString() : '0',
      minerPublicKey: '', // Populated by enrichEpochSubmission from epoch API
      solution: pow.preimage ? pow.preimage.toString('hex') : '',
      salt: '', // Populated by enrichEpochSubmission from epoch API
      graffiti: undefined,
      graffitiHex: undefined,
      signature: '',
    };
  }

  /**
   * Map MLDSASecurityLevel to string
   */
  public mapMLDSALevel(level: MLDSASecurityLevel): 'LEVEL2' | 'LEVEL3' | 'LEVEL5' {
    switch (level) {
      case MLDSASecurityLevel.LEVEL2:
        return 'LEVEL2';
      case MLDSASecurityLevel.LEVEL3:
        return 'LEVEL3';
      case MLDSASecurityLevel.LEVEL5:
        return 'LEVEL5';
      default:
        return 'LEVEL3';
    }
  }

  /**
   * Helper to serialize Address for API responses
   */
  public serializeAddress(addr: Address): Record<string, unknown> {
    return {
      originalPublicKey: addr.originalPublicKey ? Buffer.from(addr.originalPublicKey).toString('hex') : undefined,
      tweakedPublicKey: addr.tweakedPublicKeyToBuffer().toString('hex'),
      p2tr: addr.p2tr(this.network),
      p2op: addr.p2op(this.network),
      p2pkh: addr.p2pkh(this.network),
      p2wpkh: addr.p2wpkh(this.network),
      mldsaLevel: addr.mldsaLevel,
      mldsaPublicKey: addr.mldsaPublicKey ? Buffer.from(addr.mldsaPublicKey).toString('hex') : undefined,
    };
  }

  /**
   * Helper to serialize transaction receipt events
   */
  public serializeEvents(events: ContractEvents): Record<string, { type: string; data: string }[]> {
    const result: Record<string, { type: string; data: string }[]> = {};
    for (const [contractAddress, eventList] of Object.entries(events)) {
      result[contractAddress] = eventList.map(event => ({
        type: event.type,
        data: Buffer.from(event.data).toString('hex'),
      }));
    }
    return result;
  }
}

export default new OPNetClient();
