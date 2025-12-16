import { Application, Request, Response } from 'express';
import {
  TransactionBase,
  OPNetTransactionTypes,
  DeploymentTransaction,
  InteractionTransaction,
} from 'opnet';
import config from '../../config';
import logger from '../../logger';
import opnetClient from './opnet-client';
import {
  OPNetTransactionExtension,
  OPNetDeploymentData,
  OPNetInteractionData,
  OPNetGasInfo,
  OPNetEvent,
  OPNetStatusResponse,
  PostQuantumInfo,
  MLDSASecurityLevel,
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

      // Fetch MLDSA/BIP360 public key info for relevant addresses
      const addressToCheck = extension.interaction?.from || extension.deployment?.deployerAddress;
      if (addressToCheck) {
        try {
          const pubKeyInfo = await opnetClient.getPublicKeyInfo([addressToCheck]);
          if (pubKeyInfo && pubKeyInfo[addressToCheck]) {
            const addrInfo = pubKeyInfo[addressToCheck];
            // Check if MLDSA public key is linked
            if (addrInfo.mldsaPublicKey) {
              const serialized = opnetClient.serializeAddress(addrInfo);
              const mldsaLevel = (serialized.mldsaLevel as MLDSASecurityLevel) || MLDSASecurityLevel.LEVEL3;
              extension.pqInfo = {
                mldsaPublicKey: serialized.mldsaPublicKey as string,
                tweakedKey: serialized.tweakedPublicKey as string || '',
                legacySignatureType: 'schnorr',
                securityLevel: this.mapMLDSALevel(mldsaLevel),
                algorithm: mldsaLevel,
              };
            }
          }
        } catch (pubKeyErr) {
          // Non-fatal: just don't include pqInfo
          logger.debug(`Could not fetch public key info for ${addressToCheck}: ${pubKeyErr}`, this.tag);
        }
      }

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
   * Map MLDSA level to security level
   */
  private mapMLDSALevel(level: MLDSASecurityLevel): 'LEVEL2' | 'LEVEL3' | 'LEVEL5' {
    switch (level) {
      case MLDSASecurityLevel.LEVEL2: return 'LEVEL2';
      case MLDSASecurityLevel.LEVEL3: return 'LEVEL3';
      case MLDSASecurityLevel.LEVEL5: return 'LEVEL5';
      default: return 'LEVEL3';
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

      // Serialize the receipt for JSON response
      res.status(200).json({
        receipt: receipt.receipt?.toString('hex'),
        receiptProofs: receipt.receiptProofs,
        events: opnetClient.serializeEvents(receipt.events),
        revert: receipt.revert,
        gasUsed: receipt.gasUsed.toString(),
        specialGasUsed: receipt.specialGasUsed.toString(),
      });
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
            contractAddress,
            type: event.type,
            data: Buffer.from(event.data).toString('hex'),
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

      // Serialize the Address object for JSON response
      res.status(200).json(opnetClient.serializeAddress(info[address]));
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
      if (!info) {
        res.status(200).json({});
        return;
      }

      // Serialize all Address objects
      const serialized: Record<string, unknown> = {};
      for (const [addr, addressObj] of Object.entries(info)) {
        serialized[addr] = opnetClient.serializeAddress(addressObj);
      }
      res.status(200).json(serialized);
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

      // Serialize ContractData for JSON response
      res.status(200).json({
        contractAddress: code.contractAddress,
        bytecode: code.bytecode.toString('hex'),
        wasCompressed: code.wasCompressed,
        deployedTransactionId: code.deployedTransactionId,
        deployedTransactionHash: code.deployedTransactionHash,
        deployerPubKey: code.deployerPubKey.toString('hex'),
        contractSeed: code.contractSeed.toString('hex'),
        contractSaltHash: code.contractSaltHash.toString('hex'),
      });
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

      // Serialize CallResult for JSON response
      // BinaryReader doesn't have a hex conversion, so we read all bytes
      const resultBytes = result.result.readBytes(result.result.length());
      res.status(200).json({
        result: Buffer.from(resultBytes).toString('hex'),
        events: result.events,
        accessList: result.accessList,
        revert: result.revert,
        estimatedGas: result.estimatedGas?.toString(),
      });
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
  private parseOPNetTransaction(rawTx: TransactionBase<OPNetTransactionTypes>): OPNetTransactionExtension {
    const extension: OPNetTransactionExtension = {
      opnetType: rawTx.OPNetType === OPNetTransactionTypes.Deployment ? 'Deployment' :
                 rawTx.OPNetType === OPNetTransactionTypes.Interaction ? 'Interaction' : 'Generic',
    };

    // Parse deployment data
    if (rawTx.OPNetType === OPNetTransactionTypes.Deployment) {
      const deployTx = rawTx as DeploymentTransaction;
      const deployment: OPNetDeploymentData = {
        contractAddress: deployTx.contractAddress || '',
        contractPublicKey: deployTx.contractPublicKey?.toHex(),
        bytecode: deployTx.bytecode?.toString('hex') || '',
        bytecodeLength: deployTx.bytecode?.length || 0,
        deployerPubKey: deployTx.deployerPubKey?.toString('hex') || '',
        deployerAddress: deployTx.deployerAddress?.p2tr(opnetClient.getNetwork()) || '',
        contractSeed: deployTx.contractSeed?.toString('hex'),
        contractSaltHash: deployTx.contractSaltHash?.toString('hex'),
        wasCompressed: deployTx.wasCompressed,
      };
      extension.deployment = deployment;
    }

    // Parse interaction data
    if (rawTx.OPNetType === OPNetTransactionTypes.Interaction) {
      const interTx = rawTx as InteractionTransaction;
      const interaction: OPNetInteractionData = {
        calldata: interTx.calldata?.toString('hex'),
        calldataLength: interTx.calldata?.length,
        senderPubKeyHash: interTx.senderPubKeyHash?.toString('hex'),
        contractSecret: interTx.contractSecret?.toString('hex'),
        interactionPubKey: interTx.interactionPubKey?.toString('hex'),
        contractAddress: interTx.contractAddress || '',
        from: interTx.from?.p2tr(opnetClient.getNetwork()) || '',
        wasCompressed: interTx.wasCompressed,
      };
      extension.interaction = interaction;
    }

    // Parse gas info
    const gasInfo: OPNetGasInfo = {
      estimatedGas: '0',
      gasUsed: rawTx.gasUsed?.toString() || '0',
      specialGasUsed: rawTx.specialGasUsed?.toString() || '0',
    };
    extension.gasInfo = gasInfo;

    // Parse receipt (TransactionBase extends TransactionReceipt)
    if (rawTx.receipt || rawTx.receiptProofs) {
      extension.receipt = {
        receipt: rawTx.receipt?.toString('hex'),
        receiptProofs: rawTx.receiptProofs,
        events: opnetClient.serializeEvents(rawTx.events),
        revert: rawTx.revert,
        gasUsed: rawTx.gasUsed?.toString() || '0',
        specialGasUsed: rawTx.specialGasUsed?.toString() || '0',
      };
    }

    // Flatten events
    if (rawTx.events) {
      const events: OPNetEvent[] = [];
      for (const [contractAddress, contractEvents] of Object.entries(rawTx.events)) {
        for (const event of contractEvents) {
          events.push({
            contractAddress,
            type: event.type,
            data: Buffer.from(event.data).toString('hex'),
          });
        }
      }
      extension.events = events;
    }

    return extension;
  }
}

export default new OPNetRoutes();
