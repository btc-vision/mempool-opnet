import { Network, networks, script } from '@btc-vision/bitcoin';
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
const FEATURE_ACCESS_LIST = 1;
const FEATURE_EPOCH_SUBMISSION = 2;
const FEATURE_MLDSA_LINK = 4;

// OPNet header length
const OPNET_HEADER_LENGTH = 12; // 4 bytes header + 8 bytes priority fee

// MLDSA public key sizes by level (in bytes)
const MLDSA_PUBKEY_SIZES: { [key: number]: 'LEVEL2' | 'LEVEL3' | 'LEVEL5' } = {
  1312: 'LEVEL2',  // ML-DSA-44
  1952: 'LEVEL3',  // ML-DSA-65
  2592: 'LEVEL5',  // ML-DSA-87
};

// MLDSA signature sizes by level
const MLDSA_SIG_SIZES: { [level: number]: number } = {
  2: 2420,  // LEVEL2
  3: 3309,  // LEVEL3
  5: 4627,  // LEVEL5
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
   * Parse feature flags from transaction witness data
   * witness[3] is the script that needs to be decompiled
   * Header format (12 bytes): prefix(1) + flags(3 big-endian) + priorityFee(8)
   */
  private parseFeatureFlagsFromWitness(input: { transactionInWitness?: string[] }): number {
    if (!input.transactionInWitness || input.transactionInWitness.length < 4) {
      logger.debug(`[MLDSA] No witness or too few items: ${input.transactionInWitness?.length || 0}`);
      return 0;
    }

    try {
      // witness[3] is the script (index 0-2 are signatures, 3 is script, 4 is control block)
      const witnessScript = input.transactionInWitness[3];
      if (!witnessScript) {
        logger.debug('[MLDSA] No witness script at index 3');
        return 0;
      }

      logger.debug(`[MLDSA] Witness script hex (first 100 chars): ${witnessScript.substring(0, 100)}`);

      // Decompile the script
      const scriptBuffer = Buffer.from(witnessScript, 'hex');
      const decompiled = script.decompile(scriptBuffer);

      if (!decompiled || decompiled.length === 0) {
        logger.debug('[MLDSA] Failed to decompile script or empty result');
        return 0;
      }

      logger.debug(`[MLDSA] Decompiled script has ${decompiled.length} items`);

      // First item should be the OPNet header (12 bytes)
      const headerItem = decompiled[0];
      if (!Buffer.isBuffer(headerItem)) {
        logger.debug(`[MLDSA] First decompiled item is not a buffer: ${typeof headerItem}`);
        return 0;
      }

      if (headerItem.length < OPNET_HEADER_LENGTH) {
        logger.debug(`[MLDSA] Header too short: ${headerItem.length} bytes, expected ${OPNET_HEADER_LENGTH}`);
        return 0;
      }

      logger.debug(`[MLDSA] Header hex: ${headerItem.toString('hex')}`);

      // Parse header: prefix(1) + flags(3 big-endian) + priorityFee(8)
      const prefix = headerItem[0];
      // Flags are bytes 1-3, read as big-endian 24-bit integer
      const flags = headerItem.readUIntBE(1, 3);

      logger.debug(`[MLDSA] Prefix: 0x${prefix.toString(16)}, Flags: 0x${flags.toString(16)} (${flags})`);
      logger.debug(`[MLDSA] Flag check - ACCESS_LIST: ${!!(flags & FEATURE_ACCESS_LIST)}, EPOCH: ${!!(flags & FEATURE_EPOCH_SUBMISSION)}, MLDSA: ${!!(flags & FEATURE_MLDSA_LINK)}`);

      return flags;
    } catch (e) {
      logger.warn(`[MLDSA] Failed to parse feature flags: ${e}`);
      return 0;
    }
  }

  /**
   * Extract MLDSA link info from transaction witness data
   * Features are parsed in order from decompiled script after the header
   * MLDSA data format: level(u8) + hashedPubKey(32) + verifyRequest(bool) + [optional pubkey+sig] + legacySig(64)
   */
  public extractMLDSAFromWitness(tx: TransactionBase<OPNetTransactionTypes>): MLDSALinkInfo | null {
    if (!tx.inputs || tx.inputs.length === 0) {
      logger.debug('[MLDSA Extract] No inputs');
      return null;
    }

    const input = tx.inputs[0];
    if (!input.transactionInWitness || input.transactionInWitness.length < 4) {
      logger.debug(`[MLDSA Extract] Insufficient witness items: ${input.transactionInWitness?.length || 0}`);
      return null;
    }

    try {
      // Decompile witness[3] (the script)
      const witnessScript = input.transactionInWitness[3];
      if (!witnessScript) {
        logger.debug('[MLDSA Extract] No witness script at index 3');
        return null;
      }

      const scriptBuffer = Buffer.from(witnessScript, 'hex');
      const decompiled = script.decompile(scriptBuffer);

      if (!decompiled || decompiled.length < 2) {
        logger.debug(`[MLDSA Extract] Decompiled script too short: ${decompiled?.length || 0}`);
        return null;
      }

      logger.debug(`[MLDSA Extract] Decompiled script items: ${decompiled.length}`);

      // First item is the header
      const headerItem = decompiled[0];
      if (!Buffer.isBuffer(headerItem) || headerItem.length < OPNET_HEADER_LENGTH) {
        logger.debug('[MLDSA Extract] Invalid header');
        return null;
      }

      // Parse flags from header
      const flags = headerItem.readUIntBE(1, 3);
      logger.debug(`[MLDSA Extract] Flags from header: 0x${flags.toString(16)}`);

      if (!(flags & FEATURE_MLDSA_LINK)) {
        logger.debug('[MLDSA Extract] MLDSA flag not set');
        return null;
      }

      // Features are in order after header: ACCESS_LIST, EPOCH_SUBMISSION, MLDSA_LINK
      // Find the correct decompiled item index for MLDSA data
      let featureIndex = 1; // Start after header

      if (flags & FEATURE_ACCESS_LIST) {
        logger.debug(`[MLDSA Extract] Skipping ACCESS_LIST at index ${featureIndex}`);
        featureIndex++;
      }
      if (flags & FEATURE_EPOCH_SUBMISSION) {
        logger.debug(`[MLDSA Extract] Skipping EPOCH_SUBMISSION at index ${featureIndex}`);
        featureIndex++;
      }

      if (featureIndex >= decompiled.length) {
        logger.debug(`[MLDSA Extract] Feature index ${featureIndex} out of bounds (${decompiled.length} items)`);
        return null;
      }

      const mldsaItem = decompiled[featureIndex];
      if (!Buffer.isBuffer(mldsaItem)) {
        logger.debug(`[MLDSA Extract] MLDSA item at index ${featureIndex} is not a buffer`);
        return null;
      }

      logger.debug(`[MLDSA Extract] MLDSA data buffer length: ${mldsaItem.length}`);
      logger.debug(`[MLDSA Extract] MLDSA data hex: ${mldsaItem.toString('hex').substring(0, 200)}...`);

      // Parse MLDSA link request:
      // level(u8) + hashedPubKey(32) + verifyRequest(bool) + [optional pubkey+sig] + legacySig(64)
      let offset = 0;

      // Level (1 byte)
      if (mldsaItem.length < 1) {
        logger.debug('[MLDSA Extract] Buffer too short for level');
        return null;
      }
      const levelByte = mldsaItem.readUInt8(offset);
      offset += 1;
      logger.debug(`[MLDSA Extract] Level byte: ${levelByte}`);

      // Map level byte to string
      let level: 'LEVEL2' | 'LEVEL3' | 'LEVEL5';
      switch (levelByte) {
        case 2:
          level = 'LEVEL2';
          break;
        case 3:
          level = 'LEVEL3';
          break;
        case 5:
          level = 'LEVEL5';
          break;
        default:
          logger.debug(`[MLDSA Extract] Unknown level: ${levelByte}, defaulting to LEVEL3`);
          level = 'LEVEL3';
      }

      // Hashed public key (32 bytes)
      if (mldsaItem.length < offset + 32) {
        logger.debug(`[MLDSA Extract] Buffer too short for hashedPubKey at offset ${offset}`);
        return null;
      }
      const hashedPublicKey = mldsaItem.subarray(offset, offset + 32).toString('hex');
      offset += 32;
      logger.debug(`[MLDSA Extract] Hashed public key: ${hashedPublicKey}`);

      // Verify request (1 byte bool)
      if (mldsaItem.length < offset + 1) {
        logger.debug(`[MLDSA Extract] Buffer too short for verifyRequest at offset ${offset}`);
        return null;
      }
      const verifyRequest = mldsaItem.readUInt8(offset) !== 0;
      offset += 1;
      logger.debug(`[MLDSA Extract] Verify request: ${verifyRequest}`);

      let fullPublicKey: string | undefined;

      // If verify request, read optional public key and MLDSA signature
      if (verifyRequest) {
        // Public key with length prefix (varint)
        const pubKeyLen = this.readVarIntFromBuffer(mldsaItem, offset);
        offset += this.varIntSize(pubKeyLen);
        logger.debug(`[MLDSA Extract] Full public key length: ${pubKeyLen}`);

        if (mldsaItem.length < offset + pubKeyLen) {
          logger.debug(`[MLDSA Extract] Buffer too short for full public key`);
          // Continue without full key
        } else {
          fullPublicKey = mldsaItem.subarray(offset, offset + pubKeyLen).toString('hex');
          offset += pubKeyLen;
          logger.debug(`[MLDSA Extract] Full public key (first 100 chars): ${fullPublicKey.substring(0, 100)}...`);

          // MLDSA signature with length prefix
          if (mldsaItem.length > offset) {
            const sigLen = this.readVarIntFromBuffer(mldsaItem, offset);
            offset += this.varIntSize(sigLen);
            logger.debug(`[MLDSA Extract] MLDSA signature length: ${sigLen}`);
            offset += sigLen; // Skip MLDSA signature
          }
        }
      }

      // Legacy signature (64 bytes)
      let legacySignature = '';
      if (mldsaItem.length >= offset + 64) {
        legacySignature = mldsaItem.subarray(offset, offset + 64).toString('hex');
        logger.debug(`[MLDSA Extract] Legacy signature: ${legacySignature}`);
      } else {
        logger.debug(`[MLDSA Extract] No legacy signature (remaining: ${mldsaItem.length - offset} bytes)`);
      }

      logger.info(`[MLDSA Extract] Successfully parsed MLDSA: level=${level}, hashedKey=${hashedPublicKey.substring(0, 16)}...`);

      return {
        level,
        hashedPublicKey,
        fullPublicKey,
        legacySignature,
        isVerified: true,
        tweakedKey: undefined,
        originalKey: undefined,
      };
    } catch (e) {
      logger.warn(`[MLDSA Extract] Failed to parse: ${e}`);
      return null;
    }
  }

  /**
   * Read a varint from buffer (Bitcoin-style compact size)
   */
  private readVarIntFromBuffer(buffer: Buffer, offset: number): number {
    const first = buffer.readUInt8(offset);
    if (first < 0xfd) {
      return first;
    } else if (first === 0xfd) {
      return buffer.readUInt16LE(offset + 1);
    } else if (first === 0xfe) {
      return buffer.readUInt32LE(offset + 1);
    } else {
      // 0xff - 8 bytes, but we'll just read 4 for practical purposes
      return buffer.readUInt32LE(offset + 1);
    }
  }

  /**
   * Get size of varint encoding
   */
  private varIntSize(value: number): number {
    if (value < 0xfd) return 1;
    if (value <= 0xffff) return 3;
    if (value <= 0xffffffff) return 5;
    return 9;
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
