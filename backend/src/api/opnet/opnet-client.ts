import { JSONRpcProvider } from 'opnet';
import { MLDSASecurityLevel } from '@btc-vision/transaction';
import config from '../../config';
import logger from '../../logger';
import {
  OPNetPublicKeyInfo,
  OPNetTransactionReceipt,
  OPNetCallResult,
  OPNetRawTransaction,
} from './opnet.interfaces';

class OPNetClient {
  private provider: JSONRpcProvider | null = null;
  private enabled: boolean;
  private connected: boolean = false;
  private lastError: string | null = null;

  constructor() {
    this.enabled = config.OPNET.ENABLED;

    if (this.enabled) {
      this.initProvider();
    }
  }

  private initProvider(): void {
    try {
      this.provider = new JSONRpcProvider(config.OPNET.RPC_URL, {
        timeout: config.OPNET.TIMEOUT,
      });
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
  public async getTransaction(txHash: string): Promise<OPNetRawTransaction | null> {
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

      // The provider returns the parsed transaction
      return tx as unknown as OPNetRawTransaction;
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getTransaction failed for ${txHash}: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get transaction receipt
   */
  public async getTransactionReceipt(txHash: string): Promise<OPNetTransactionReceipt | null> {
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

      return {
        receipt: receipt.receipt,
        receiptProofs: receipt.receiptProofs,
        events: receipt.events,
        revert: receipt.revert,
        gasUsed: receipt.gasUsed?.toString() || '0',
        specialGasUsed: receipt.specialGasUsed?.toString() || '0',
      };
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getTransactionReceipt failed for ${txHash}: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get public key info (MLDSA/BIP360)
   */
  public async getPublicKeyInfo(addresses: string[]): Promise<Record<string, OPNetPublicKeyInfo> | null> {
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

      // Convert to our interface format
      const result: Record<string, OPNetPublicKeyInfo> = {};
      for (const [address, pubKeyInfo] of Object.entries(info)) {
        result[address] = {
          originalPubKey: pubKeyInfo.originalPubKey,
          tweakedPubkey: pubKeyInfo.tweakedPubkey,
          p2tr: pubKeyInfo.p2tr,
          p2op: pubKeyInfo.p2op,
          lowByte: pubKeyInfo.lowByte,
          p2pkh: pubKeyInfo.p2pkh,
          p2wpkh: pubKeyInfo.p2wpkh,
          mldsaHashedPublicKey: pubKeyInfo.mldsaHashedPublicKey,
          mldsaLevel: pubKeyInfo.mldsaLevel as MLDSASecurityLevel,
          mldsaPublicKey: pubKeyInfo.mldsaPublicKey,
        };
      }

      return result;
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
    to: string,
    data: string,
    from?: string,
    height?: number
  ): Promise<OPNetCallResult | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const result = await this.provider.call(to, data, from, height);
      if (!result) {
        return null;
      }

      this.connected = true;
      this.lastError = null;

      return {
        result: result.result?.toString() || '',
        events: result.events || {},
        accessList: result.accessList || {},
        revert: result.revert,
        estimatedGas: result.estimatedGas?.toString(),
        specialGas: result.specialGas?.toString(),
      };
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet call failed to ${to}: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get contract bytecode
   */
  public async getCode(address: string): Promise<{ bytecode: string } | null> {
    if (!this.enabled || !this.provider) {
      return null;
    }

    try {
      const code = await this.provider.getCode(address);
      if (!code) {
        return null;
      }

      this.connected = true;
      this.lastError = null;

      return { bytecode: code.bytecode || '' };
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      logger.warn(`OPNet getCode failed for ${address}: ${this.lastError}`);
      return null;
    }
  }

  /**
   * Get storage at address
   */
  public async getStorageAt(address: string, pointer: string): Promise<string | null> {
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
}

export default new OPNetClient();
