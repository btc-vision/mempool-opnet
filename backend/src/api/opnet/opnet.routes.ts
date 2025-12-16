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
  OPNetFeatures,
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

      // Debug: Log parsed extension
      logger.debug(`Parsed tx ${txId}: type=${extension.opnetType}, hasMLDSA=${extension.features.hasMLDSALink}, hasEpoch=${extension.features.hasEpochSubmission}`, this.tag);
      if (extension.mldsaLink) {
        logger.debug(`  mldsaLink: level=${extension.mldsaLink.level}, hashedKey=${extension.mldsaLink.hashedPublicKey?.substring(0, 16)}...`, this.tag);
      }

      // Fetch full epoch submission data if this tx has epoch submission
      if (extension.features.hasEpochSubmission && rawTx.blockNumber) {
        try {
          await this.enrichEpochSubmission(extension, txId, rawTx.blockNumber);
        } catch (epochErr) {
          logger.debug(`Could not fetch epoch data for ${txId}: ${epochErr}`, this.tag);
        }
      }

      // Fetch MLDSA/BIP360 public key info for relevant addresses
      const addressToCheck = extension.interaction?.from || extension.deployment?.deployerAddress;
      logger.debug(`Checking MLDSA for address: ${addressToCheck}`, this.tag);
      if (addressToCheck) {
        try {
          const pubKeyInfo = await opnetClient.getPublicKeyInfo([addressToCheck]);
          logger.debug(`getPublicKeyInfo returned: ${pubKeyInfo ? 'data' : 'null'}, has address key: ${!!(pubKeyInfo && pubKeyInfo[addressToCheck])}`, this.tag);
          if (pubKeyInfo && pubKeyInfo[addressToCheck]) {
            const addrInfo = pubKeyInfo[addressToCheck];
            logger.debug(`addrInfo mldsaPublicKey: ${addrInfo.mldsaPublicKey ? 'present (' + (addrInfo.mldsaPublicKey as Uint8Array).length + ' bytes)' : 'missing'}, mldsaLevel: ${addrInfo.mldsaLevel}`, this.tag);
            // Check if MLDSA public key is linked
            if (addrInfo.mldsaPublicKey) {
              const serialized = opnetClient.serializeAddress(addrInfo);
              const mldsaLevel = (serialized.mldsaLevel as MLDSASecurityLevel) || MLDSASecurityLevel.LEVEL3;

              // Extract detailed MLDSA link info using the new method
              const mldsaLink = opnetClient.extractMLDSALinkInfo(addrInfo);
              if (mldsaLink) {
                extension.mldsaLink = mldsaLink;
                // Update features to reflect MLDSA link detection
                extension.features.hasMLDSALink = true;
                extension.features.featureFlags |= 0b100; // FEATURE_MLDSA_LINK
              }

              // Keep pqInfo for backward compatibility
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
   * Enrich epoch submission with full data from epoch API
   */
  private async enrichEpochSubmission(
    extension: OPNetTransactionExtension,
    txId: string,
    blockNumber: bigint
  ): Promise<void> {
    // Calculate epoch number from block height (2016 blocks per epoch)
    const blocksPerEpoch = 2016n;
    const epochNumber = blockNumber / blocksPerEpoch;

    // Fetch the epoch with submissions
    const epochData = await opnetClient.getEpochByNumber(epochNumber, true);
    if (!epochData) {
      logger.debug(`Epoch ${epochNumber} not found`, this.tag);
      return;
    }

    // Check if this is EpochWithSubmissions (has submissions array)
    const epochWithSubs = epochData as import('opnet').EpochWithSubmissions;
    if (!epochWithSubs.submissions || epochWithSubs.submissions.length === 0) {
      // No submissions in this epoch, use basic epoch data
      if (extension.epochSubmission) {
        extension.epochSubmission.epochNumber = epochNumber.toString();
      }
      return;
    }

    // Find the matching submission by transaction ID
    const matchingSubmission = epochWithSubs.submissions.find(sub => {
      const subTxId = sub.submissionTxId.toString('hex');
      const subTxHash = sub.submissionTxHash.toString('hex');
      return subTxId === txId || subTxHash === txId;
    });

    if (matchingSubmission) {
      // Found the submission - extract full data
      const miner = matchingSubmission.epochProposed;
      extension.epochSubmission = {
        epochNumber: epochNumber.toString(),
        minerPublicKey: miner.publicKey.p2tr(opnetClient.getNetwork()),
        solution: miner.solution.toString('hex'),
        salt: miner.salt.toString('hex'),
        graffiti: miner.graffiti ? miner.graffiti.toString('utf8') : undefined,
        graffitiHex: miner.graffiti ? miner.graffiti.toString('hex') : undefined,
        signature: matchingSubmission.submissionHash.toString('hex'),
      };
    } else {
      // Submission not found in epoch, but tx has PoW data
      // Use the proposer data from the epoch as fallback info
      if (extension.epochSubmission) {
        extension.epochSubmission.epochNumber = epochNumber.toString();
      }
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
    // Parse feature flags from transaction
    const features: OPNetFeatures = opnetClient.parseFeatures(rawTx);

    const extension: OPNetTransactionExtension = {
      opnetType: rawTx.OPNetType === OPNetTransactionTypes.Deployment ? 'Deployment' :
                 rawTx.OPNetType === OPNetTransactionTypes.Interaction ? 'Interaction' : 'Generic',
      features,
    };

    // Extract epoch submission info if present
    const epochSubmission = opnetClient.extractEpochSubmission(rawTx);
    if (epochSubmission) {
      // Populate miner public key from transaction sender if available
      if (rawTx.OPNetType === OPNetTransactionTypes.Interaction) {
        const interTx = rawTx as InteractionTransaction;
        if (interTx.from) {
          epochSubmission.minerPublicKey = interTx.from.p2tr(opnetClient.getNetwork());
        }
      }
      // Compute epoch number from block height if available
      if (rawTx.blockNumber) {
        const blocksPerEpoch = 2016n;
        const epochNum = rawTx.blockNumber / blocksPerEpoch;
        epochSubmission.epochNumber = epochNum.toString();
      }
      extension.epochSubmission = epochSubmission;
    }

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

      // Extract MLDSA info from deployer Address if available
      if (deployTx.deployerAddress && typeof deployTx.deployerAddress !== 'string') {
        const mldsaLink = opnetClient.extractMLDSALinkInfo(deployTx.deployerAddress);
        if (mldsaLink) {
          extension.mldsaLink = mldsaLink;
          extension.features.hasMLDSALink = true;
          extension.features.featureFlags |= 0b100; // FEATURE_MLDSA_LINK
          logger.debug(`MLDSA link found in deployer address: ${mldsaLink.level}`, this.tag);
        }
      }
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

      // Extract MLDSA info directly from the sender Address object if available
      if (interTx.from && typeof interTx.from !== 'string') {
        logger.debug(`interTx.from type: ${Object.prototype.toString.call(interTx.from)}, keys: ${Object.keys(interTx.from || {}).join(',')}`, this.tag);
        const mldsaLink = opnetClient.extractMLDSALinkInfo(interTx.from);
        if (mldsaLink) {
          extension.mldsaLink = mldsaLink;
          extension.features.hasMLDSALink = true;
          extension.features.featureFlags |= 0b100; // FEATURE_MLDSA_LINK
          logger.debug(`MLDSA link found in tx from address: ${mldsaLink.level}`, this.tag);
        }
      } else if (interTx.from) {
        logger.debug(`interTx.from is string: ${interTx.from}`, this.tag);
      }
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
