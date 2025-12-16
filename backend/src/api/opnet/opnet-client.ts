import { Network, networks } from '@btc-vision/bitcoin';
import { Address } from '@btc-vision/transaction';
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
  EpochSubmissionInfo,
} from './opnet.interfaces';

// Feature flags from @btc-vision/transaction
const FEATURE_ACCESS_LIST = 1;
const FEATURE_EPOCH_SUBMISSION = 2;

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
   * Note: MLDSA/BIP360 is parsed on the frontend from raw witness data (electrs provides it)
   */
  public parseFeatures(tx: TransactionBase<OPNetTransactionTypes>): OPNetFeatures {
    const features: OPNetFeatures = {
      hasAccessList: false,
      hasEpochSubmission: false,
      hasMLDSALink: false,
      featureFlags: 0,
    };

    // Check for access list (present in interaction transactions with events)
    if (tx.OPNetType === OPNetTransactionTypes.Interaction) {
      features.hasAccessList = true;
      features.featureFlags |= FEATURE_ACCESS_LIST;
    }

    // Check for epoch submission (PoW challenge data present)
    if (tx.pow) {
      features.hasEpochSubmission = true;
      features.featureFlags |= FEATURE_EPOCH_SUBMISSION;
    }

    // Note: MLDSA detection happens on frontend using electrs witness data
    // The OPNet API doesn't provide transactionInWitness

    return features;
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
