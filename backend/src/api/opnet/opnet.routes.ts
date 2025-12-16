import { Application, Request, Response } from 'express';
import config from '../../config';
import logger from '../../logger';
import opnetClient from './opnet-client';
import {
  OPNetTransactionExtension,
  OPNetDeploymentData,
  OPNetInteractionData,
  OPNetGasInfo,
  OPNetEvent,
  PostQuantumInfo,
  OPNetStatusResponse,
} from './opnet.interfaces';

class OPNetRoutes {
  private tag = 'OPNet';

  public initRoutes(app: Application): void {
    // Only register routes if OPNet is enabled
    if (!config.OPNET.ENABLED) {
      logger.info('OPNet routes not registered (OPNET.ENABLED is false)', this.tag);
      return;
    }

    logger.info('Registering OPNet API routes', this.tag);

    app
      // Transaction enrichment
      .get(config.MEMPOOL.API_URL_PREFIX + 'opnet/tx/:txId', this.$getOPNetTransaction.bind(this))
      .get(config.MEMPOOL.API_URL_PREFIX + 'opnet/tx/:txId/receipt', this.$getTransactionReceipt.bind(this))
      .get(config.MEMPOOL.API_URL_PREFIX + 'opnet/tx/:txId/events', this.$getTransactionEvents.bind(this))

      // Public key / MLDSA info
      .get(config.MEMPOOL.API_URL_PREFIX + 'opnet/address/:address/pubkey', this.$getPublicKeyInfo.bind(this))
      .post(config.MEMPOOL.API_URL_PREFIX + 'opnet/pubkeys', this.$getBatchPublicKeyInfo.bind(this))

      // Contract info
      .get(config.MEMPOOL.API_URL_PREFIX + 'opnet/contract/:address/code', this.$getContractCode.bind(this))
      .get(config.MEMPOOL.API_URL_PREFIX + 'opnet/contract/:address/storage/:pointer', this.$getStorageAt.bind(this))

      // Contract call simulation
      .post(config.MEMPOOL.API_URL_PREFIX + 'opnet/call', this.$simulateCall.bind(this))

      // Backend info extension
      .get(config.MEMPOOL.API_URL_PREFIX + 'opnet/status', this.$getOPNetStatus.bind(this));
  }

  /**
   * Get enriched transaction with OPNet-specific data
   */
  private async $getOPNetTransaction(req: Request, res: Response): Promise<void> {
    const { txId } = req.params;

    if (!txId || txId.length !== 64) {
      res.status(400).json({ error: 'Invalid transaction ID' });
      return;
    }

    try {
      const rawTx = await opnetClient.getTransaction(txId);
      if (!rawTx) {
        res.status(404).json({ error: 'Transaction not found in OPNet' });
        return;
      }

      const extension = this.parseOPNetTransaction(rawTx);
      res.status(200).json({
        txid: txId,
        opnet: extension,
      });
    } catch (e) {
      logger.err(`Error fetching OPNet transaction ${txId}: ${e}`, this.tag);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Get transaction receipt
   */
  private async $getTransactionReceipt(req: Request, res: Response): Promise<void> {
    const { txId } = req.params;

    if (!txId || txId.length !== 64) {
      res.status(400).json({ error: 'Invalid transaction ID' });
      return;
    }

    try {
      const receipt = await opnetClient.getTransactionReceipt(txId);
      if (!receipt) {
        res.status(404).json({ error: 'Receipt not found' });
        return;
      }

      res.status(200).json(receipt);
    } catch (e) {
      logger.err(`Error fetching transaction receipt ${txId}: ${e}`, this.tag);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Get transaction events
   */
  private async $getTransactionEvents(req: Request, res: Response): Promise<void> {
    const { txId } = req.params;

    if (!txId || txId.length !== 64) {
      res.status(400).json({ error: 'Invalid transaction ID' });
      return;
    }

    try {
      const rawTx = await opnetClient.getTransaction(txId);
      if (!rawTx || !rawTx.events) {
        res.status(404).json({ error: 'Events not found' });
        return;
      }

      // Flatten events from all contracts
      const events: OPNetEvent[] = [];
      for (const [contractAddress, contractEvents] of Object.entries(rawTx.events)) {
        for (const event of contractEvents) {
          events.push({
            ...event,
            contractAddress,
          });
        }
      }

      res.status(200).json(events);
    } catch (e) {
      logger.err(`Error fetching transaction events ${txId}: ${e}`, this.tag);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Get public key info for a single address
   */
  private async $getPublicKeyInfo(req: Request, res: Response): Promise<void> {
    const { address } = req.params;

    if (!address) {
      res.status(400).json({ error: 'Address is required' });
      return;
    }

    try {
      const info = await opnetClient.getPublicKeyInfo([address]);
      if (!info || !info[address]) {
        res.status(404).json({ error: 'Public key info not found' });
        return;
      }

      res.status(200).json(info[address]);
    } catch (e) {
      logger.err(`Error fetching public key info for ${address}: ${e}`, this.tag);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Get public key info for multiple addresses
   */
  private async $getBatchPublicKeyInfo(req: Request, res: Response): Promise<void> {
    const { addresses } = req.body;

    if (!addresses || !Array.isArray(addresses) || addresses.length === 0) {
      res.status(400).json({ error: 'Addresses array is required' });
      return;
    }

    if (addresses.length > 100) {
      res.status(400).json({ error: 'Maximum 100 addresses per request' });
      return;
    }

    try {
      const info = await opnetClient.getPublicKeyInfo(addresses);
      res.status(200).json(info || {});
    } catch (e) {
      logger.err(`Error fetching batch public key info: ${e}`, this.tag);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Get contract bytecode
   */
  private async $getContractCode(req: Request, res: Response): Promise<void> {
    const { address } = req.params;

    if (!address) {
      res.status(400).json({ error: 'Contract address is required' });
      return;
    }

    try {
      const code = await opnetClient.getCode(address);
      if (!code) {
        res.status(404).json({ error: 'Contract code not found' });
        return;
      }

      res.status(200).json(code);
    } catch (e) {
      logger.err(`Error fetching contract code for ${address}: ${e}`, this.tag);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Get storage at pointer
   */
  private async $getStorageAt(req: Request, res: Response): Promise<void> {
    const { address, pointer } = req.params;

    if (!address || !pointer) {
      res.status(400).json({ error: 'Contract address and pointer are required' });
      return;
    }

    try {
      const value = await opnetClient.getStorageAt(address, pointer);
      res.status(200).json({ value: value || '0x' });
    } catch (e) {
      logger.err(`Error fetching storage at ${address}:${pointer}: ${e}`, this.tag);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Simulate contract call
   */
  private async $simulateCall(req: Request, res: Response): Promise<void> {
    const { to, data, from, height } = req.body;

    if (!to || !data) {
      res.status(400).json({ error: 'Contract address (to) and calldata (data) are required' });
      return;
    }

    try {
      const result = await opnetClient.call(to, data, from, height);
      if (!result) {
        res.status(500).json({ error: 'Call simulation failed' });
        return;
      }

      res.status(200).json(result);
    } catch (e) {
      logger.err(`Error simulating call to ${to}: ${e}`, this.tag);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Get OPNet connection status
   */
  private async $getOPNetStatus(req: Request, res: Response): Promise<void> {
    const status: OPNetStatusResponse = {
      enabled: opnetClient.isEnabled(),
      connected: opnetClient.isConnected(),
      rpcUrl: config.OPNET.RPC_URL,
      lastError: opnetClient.getLastError() || undefined,
    };

    res.status(200).json(status);
  }

  /**
   * Parse raw OPNet transaction into extension format
   */
  private parseOPNetTransaction(rawTx: any): OPNetTransactionExtension {
    const extension: OPNetTransactionExtension = {
      opnetType: rawTx.OPNetType || 'Generic',
    };

    // Parse deployment data
    if (rawTx.OPNetType === 'Deployment' && rawTx.contractAddress) {
      const deployment: OPNetDeploymentData = {
        contractAddress: rawTx.contractAddress,
        contractPublicKey: rawTx.contractPublicKey,
        bytecode: rawTx.bytecode || '',
        bytecodeLength: rawTx.bytecode ? Buffer.from(rawTx.bytecode, 'base64').length : 0,
        deployerPubKey: rawTx.deployerPubKey || '',
        deployerAddress: rawTx.from || '',
        contractSeed: rawTx.contractSeed,
        contractSaltHash: rawTx.contractSaltHash,
        wasCompressed: rawTx.wasCompressed,
      };
      extension.deployment = deployment;
    }

    // Parse interaction data
    if (rawTx.OPNetType === 'Interaction' && rawTx.contractAddress) {
      const interaction: OPNetInteractionData = {
        calldata: rawTx.calldata,
        calldataLength: rawTx.calldata ? Buffer.from(rawTx.calldata, 'base64').length : 0,
        senderPubKeyHash: rawTx.senderPubKeyHash,
        contractSecret: rawTx.contractSecret,
        interactionPubKey: rawTx.interactionPubKey,
        contractAddress: rawTx.contractAddress,
        from: rawTx.from || '',
        wasCompressed: rawTx.wasCompressed,
      };
      extension.interaction = interaction;
    }

    // Parse gas info
    if (rawTx.gasUsed || rawTx.specialGasUsed) {
      const gasInfo: OPNetGasInfo = {
        estimatedGas: rawTx.estimatedGas || '0',
        gasUsed: rawTx.gasUsed || '0',
        specialGasUsed: rawTx.specialGasUsed || '0',
        refundedGas: rawTx.refundedGas,
      };
      extension.gasInfo = gasInfo;
    }

    // Parse receipt
    if (rawTx.receipt || rawTx.receiptProofs) {
      extension.receipt = {
        receipt: rawTx.receipt,
        receiptProofs: rawTx.receiptProofs,
        events: rawTx.events,
        revert: rawTx.revert,
        gasUsed: rawTx.gasUsed || '0',
        specialGasUsed: rawTx.specialGasUsed || '0',
      };
    }

    // Flatten events
    if (rawTx.events) {
      const events: OPNetEvent[] = [];
      for (const [contractAddress, contractEvents] of Object.entries(rawTx.events)) {
        for (const event of contractEvents as OPNetEvent[]) {
          events.push({
            ...event,
            contractAddress,
          });
        }
      }
      extension.events = events;
    }

    return extension;
  }
}

export default new OPNetRoutes();
