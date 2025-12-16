/**
 * OPNet Witness Data Parsing Utilities
 * Parses MLDSA/BIP360 and other feature data from raw transaction witness
 *
 * Based on OPNet transaction structure using BinaryReader from @btc-vision/transaction
 */

import { BinaryReader } from '@btc-vision/transaction';
import { MLDSALinkInfo, OPNetFeatures, EpochSubmissionInfo } from '@interfaces/electrs.interface';

// Feature flags (from @btc-vision/transaction Features enum)
const FEATURE_ACCESS_LIST = 0b1;        // 1
const FEATURE_EPOCH_SUBMISSION = 0b10;  // 2
const FEATURE_MLDSA_LINK = 0b100;       // 4

// OPNet header is 12 bytes: prefix(1) + flags(3) + priorityFee(8)
const OPNET_HEADER_LENGTH = 12;

// OP codes
const OP_TOALTSTACK = 0x6b;

/**
 * Parse OPNet features from raw witness data
 * witness[3] is the script containing the OPNet data
 */
export function parseOPNetFeaturesFromWitness(witness: string[]): OPNetFeatures | null {
  if (!witness || witness.length < 4) {
    console.log('[OPNet] parseFeatures: witness too short, length:', witness?.length);
    return null;
  }

  try {
    const script = witness[3];
    if (!script) {
      console.log('[OPNet] parseFeatures: witness[3] is empty');
      return null;
    }

    console.log('[OPNet] parseFeatures: script length:', script.length, 'first 100 chars:', script.substring(0, 100));

    const bytes = hexToBytes(script);
    const reader = new BinaryReader(bytes);

    // Read header push opcode and data
    const headerLen = reader.readU8();
    if (headerLen !== OPNET_HEADER_LENGTH) {
      console.log('[OPNet] parseFeatures: header length mismatch, got:', headerLen, 'expected:', OPNET_HEADER_LENGTH);
      return null;
    }

    const header = reader.readBytes(OPNET_HEADER_LENGTH);
    console.log('[OPNet] parseFeatures: header bytes:', toHex(header));

    // Parse header: prefix(1) + flags(3 big-endian) + priorityFee(8)
    const prefix = header[0];
    if (prefix !== 0x02 && prefix !== 0x03) {
      console.log('[OPNet] parseFeatures: invalid prefix:', prefix.toString(16));
      return null; // Invalid public key prefix
    }

    // Flags are bytes 1-3, read as big-endian 24-bit integer
    const flags = (header[1] << 16) | (header[2] << 8) | header[3];
    console.log('[OPNet] parseFeatures: flags=', flags, 'binary:', flags.toString(2).padStart(24, '0'));
    console.log('[OPNet] parseFeatures: hasAccessList:', (flags & FEATURE_ACCESS_LIST) !== 0);
    console.log('[OPNet] parseFeatures: hasEpochSubmission:', (flags & FEATURE_EPOCH_SUBMISSION) !== 0);
    console.log('[OPNet] parseFeatures: hasMLDSALink:', (flags & FEATURE_MLDSA_LINK) !== 0);

    return {
      hasAccessList: (flags & FEATURE_ACCESS_LIST) !== 0,
      hasEpochSubmission: (flags & FEATURE_EPOCH_SUBMISSION) !== 0,
      hasMLDSALink: (flags & FEATURE_MLDSA_LINK) !== 0,
      featureFlags: flags,
    };
  } catch (e) {
    console.warn('[OPNet] Failed to parse features from witness:', e);
    return null;
  }
}

/**
 * Extract Epoch Submission info from witness data
 * Epoch submission format: mldsaPublicKey(32) + salt(32) + graffiti(optional with length)
 * Note: Epoch NUMBER is calculated from block height, not stored in witness
 */
export function extractEpochSubmissionFromWitness(witness: string[], blockHeight?: number): EpochSubmissionInfo | null {
  if (!witness || witness.length < 4) {
    return null;
  }

  try {
    const script = witness[3];
    if (!script) {
      return null;
    }

    const bytes = hexToBytes(script);

    // Parse the script structure to find features data
    const parsed = parseOPNetScript(bytes);
    if (!parsed || !parsed.featuresData) {
      return null;
    }

    // Check if epoch submission flag is set
    if (!(parsed.flags & FEATURE_EPOCH_SUBMISSION)) {
      return null;
    }

    // Decode features in priority order
    const features = decodeFeaturesData(parsed.flags, parsed.featuresData);
    const epochFeature = features.find(f => f.type === 'epoch');

    if (!epochFeature || !epochFeature.data) {
      return null;
    }

    // Parse epoch submission: mldsaPublicKey(32) + salt(32) + graffiti(optional)
    const reader = new BinaryReader(epochFeature.data);
    if (reader.length() < 64) {
      return null;
    }

    const minerPublicKey = toHex(reader.readBytes(32));
    const salt = toHex(reader.readBytes(32));

    // Graffiti is optional - remaining bytes
    let graffiti: string | undefined;
    let graffitiHex: string | undefined;
    if (reader.bytesLeft() > 0) {
      const graffitiLen = reader.readU8();
      if (graffitiLen > 0 && reader.bytesLeft() >= graffitiLen) {
        const graffitiBytes = reader.readBytes(graffitiLen);
        graffitiHex = toHex(graffitiBytes);
        try {
          graffiti = new TextDecoder().decode(graffitiBytes);
        } catch {
          graffiti = undefined;
        }
      }
    }

    // Calculate epoch number from block height (5 blocks per epoch in OPNet)
    const epochNumber = blockHeight ? Math.floor(blockHeight / 5).toString() : '0';

    return {
      epochNumber,
      minerPublicKey,
      solution: parsed.preimage ? toHex(parsed.preimage) : '',
      salt,
      graffiti,
      graffitiHex,
      signature: '',
    };
  } catch (e) {
    console.warn('[OPNet] Failed to extract epoch submission from witness:', e);
    return null;
  }
}

/**
 * Extract MLDSA/BIP360 link info from witness data
 * MLDSA format: level(u8) + hashedPubKey(32) + verifyRequest(bool) + [optional pubkey+sig] + legacySig(64)
 *
 * Level values (MLDSASecurityLevel enum):
 * - 0 = LEVEL2 (ML-DSA-44)
 * - 1 = LEVEL3 (ML-DSA-65)
 * - 2 = LEVEL5 (ML-DSA-87)
 */
export function extractMLDSAFromWitness(witness: string[]): MLDSALinkInfo | null {
  console.log('[OPNet] extractMLDSA: starting...');
  if (!witness || witness.length < 4) {
    console.log('[OPNet] extractMLDSA: witness too short');
    return null;
  }

  try {
    const script = witness[3];
    if (!script) {
      console.log('[OPNet] extractMLDSA: witness[3] is empty');
      return null;
    }

    const bytes = hexToBytes(script);
    console.log('[OPNet] extractMLDSA: script bytes length:', bytes.length);

    // Parse the script structure to find features data
    const parsed = parseOPNetScript(bytes);
    if (!parsed) {
      console.log('[OPNet] extractMLDSA: parseOPNetScript returned null');
      return null;
    }
    console.log('[OPNet] extractMLDSA: parsed script, flags:', parsed.flags, 'featuresData:', parsed.featuresData?.length);

    if (!parsed.featuresData) {
      console.log('[OPNet] extractMLDSA: no features data');
      return null;
    }

    // Check if MLDSA link flag is set
    if (!(parsed.flags & FEATURE_MLDSA_LINK)) {
      console.log('[OPNet] extractMLDSA: MLDSA flag not set, flags:', parsed.flags);
      return null;
    }

    // Decode features in priority order
    const features = decodeFeaturesData(parsed.flags, parsed.featuresData);
    console.log('[OPNet] extractMLDSA: decoded features:', features.map(f => ({ type: f.type, len: f.data.length })));

    const mldsaFeature = features.find(f => f.type === 'mldsa');

    if (!mldsaFeature || !mldsaFeature.data) {
      console.log('[OPNet] extractMLDSA: no mldsa feature found');
      return null;
    }

    console.log('[OPNet] extractMLDSA: mldsa data length:', mldsaFeature.data.length, 'first 50 bytes:', toHex(mldsaFeature.data.slice(0, 50)));

    const result = parseMLDSAData(mldsaFeature.data);
    console.log('[OPNet] extractMLDSA: result:', result);
    return result;
  } catch (e) {
    console.warn('[OPNet] Failed to extract MLDSA from witness:', e);
    return null;
  }
}

/**
 * Parse the OPNet script structure
 */
interface ParsedOPNetScript {
  header: Uint8Array;
  flags: number;
  minerMLDSAPublicKey: Uint8Array;
  preimage: Uint8Array;
  featuresData: Uint8Array | null;
}

function parseOPNetScript(bytes: Uint8Array): ParsedOPNetScript | null {
  console.log('[OPNet] parseScript: total bytes:', bytes.length);
  const reader = new BinaryReader(bytes);

  try {
    // 1. Read header push opcode + data (12 bytes)
    const headerPushLen = reader.readU8();
    if (headerPushLen !== OPNET_HEADER_LENGTH) {
      console.log('[OPNet] parseScript: header push length mismatch:', headerPushLen);
      return null;
    }
    const header = reader.readBytes(OPNET_HEADER_LENGTH);
    console.log('[OPNet] parseScript: header:', toHex(header));

    // Check OP_TOALTSTACK
    const op1 = reader.readU8();
    if (op1 !== OP_TOALTSTACK) {
      console.log('[OPNet] parseScript: expected OP_TOALTSTACK, got:', op1.toString(16));
      return null;
    }

    // 2. Read minerMLDSAPublicKey (32 bytes)
    const minerKeyPushLen = reader.readU8();
    if (minerKeyPushLen !== 32) {
      console.log('[OPNet] parseScript: minerKey push length mismatch:', minerKeyPushLen);
      return null;
    }
    const minerMLDSAPublicKey = reader.readBytes(32);
    console.log('[OPNet] parseScript: minerKey:', toHex(minerMLDSAPublicKey));

    // Check OP_TOALTSTACK
    const op2 = reader.readU8();
    if (op2 !== OP_TOALTSTACK) {
      console.log('[OPNet] parseScript: expected OP_TOALTSTACK (2), got:', op2.toString(16));
      return null;
    }

    // 3. Read preimage/solution (variable length)
    const preimageLen = readPushDataLength(reader);
    if (preimageLen === null) {
      console.log('[OPNet] parseScript: preimage length read failed');
      return null;
    }
    const preimage = reader.readBytes(preimageLen);
    console.log('[OPNet] parseScript: preimage length:', preimage.length);

    // Check OP_TOALTSTACK
    const op3 = reader.readU8();
    if (op3 !== OP_TOALTSTACK) {
      console.log('[OPNet] parseScript: expected OP_TOALTSTACK (3), got:', op3.toString(16));
      return null;
    }

    // Parse flags from header
    const flags = (header[1] << 16) | (header[2] << 8) | header[3];
    console.log('[OPNet] parseScript: flags:', flags, 'binary:', flags.toString(2));

    // 4. Read features data (if any flags are set)
    let featuresData: Uint8Array | null = null;
    if (flags !== 0 && reader.bytesLeft() > 0) {
      console.log('[OPNet] parseScript: reading features data, remaining bytes:', reader.bytesLeft());
      const featuresLen = readPushDataLength(reader);
      if (featuresLen !== null && reader.bytesLeft() >= featuresLen) {
        featuresData = reader.readBytes(featuresLen);
        console.log('[OPNet] parseScript: features data length:', featuresData.length, 'hex:', toHex(featuresData.slice(0, 100)));
      } else {
        console.log('[OPNet] parseScript: features read failed, featuresLen:', featuresLen);
      }
    } else {
      console.log('[OPNet] parseScript: no features data (flags:', flags, 'bytesLeft:', reader.bytesLeft(), ')');
    }

    return {
      header,
      flags,
      minerMLDSAPublicKey,
      preimage,
      featuresData,
    };
  } catch (e) {
    console.log('[OPNet] parseScript: exception:', e);
    return null;
  }
}

/**
 * Read push data length from script (handles OP_PUSHBYTES_*, OP_PUSHDATA1/2/4)
 */
function readPushDataLength(reader: BinaryReader): number | null {
  const opcode = reader.readU8();

  // OP_PUSHBYTES_1 to OP_PUSHBYTES_75
  if (opcode >= 0x01 && opcode <= 0x4b) {
    return opcode;
  }
  // OP_PUSHDATA1
  else if (opcode === 0x4c) {
    return reader.readU8();
  }
  // OP_PUSHDATA2
  else if (opcode === 0x4d) {
    return reader.readU16(false); // little-endian
  }
  // OP_PUSHDATA4
  else if (opcode === 0x4e) {
    return reader.readU32(false); // little-endian
  }

  return null;
}

interface DecodedFeature {
  type: 'accessList' | 'epoch' | 'mldsa';
  data: Uint8Array;
}

/**
 * Decode features data based on flags
 * Features are stored with U32 length prefixes (big-endian) and decoded in priority order:
 * 1. ACCESS_LIST
 * 2. EPOCH_SUBMISSION
 * 3. MLDSA_LINK_PUBKEY
 */
function decodeFeaturesData(flags: number, data: Uint8Array): DecodedFeature[] {
  const features: DecodedFeature[] = [];
  const reader = new BinaryReader(data);
  console.log('[OPNet] decodeFeatures: flags:', flags, 'data length:', data.length, 'first 20 bytes:', toHex(data.slice(0, Math.min(20, data.length))));

  // Decode in priority order
  const featureOrder: Array<{ flag: number; type: DecodedFeature['type'] }> = [
    { flag: FEATURE_ACCESS_LIST, type: 'accessList' },
    { flag: FEATURE_EPOCH_SUBMISSION, type: 'epoch' },
    { flag: FEATURE_MLDSA_LINK, type: 'mldsa' },
  ];

  for (const { flag, type } of featureOrder) {
    if (flags & flag) {
      console.log('[OPNet] decodeFeatures: reading', type, 'bytesLeft:', reader.bytesLeft());

      if (reader.bytesLeft() < 4) {
        console.log('[OPNet] decodeFeatures:', type, 'not enough bytes for length');
        break;
      }

      // Read U32 length prefix (big-endian)
      const len = reader.readU32(true);
      console.log('[OPNet] decodeFeatures:', type, 'length:', len);

      if (len > 0 && reader.bytesLeft() >= len) {
        const featureData = reader.readBytes(len);
        console.log('[OPNet] decodeFeatures:', type, 'data read, actual length:', featureData.length);
        features.push({
          type,
          data: featureData,
        });
      } else {
        console.log('[OPNet] decodeFeatures:', type, 'invalid length or not enough data, len:', len, 'bytesLeft:', reader.bytesLeft());
      }
    }
  }

  console.log('[OPNet] decodeFeatures: total features:', features.length);
  return features;
}

/**
 * Parse MLDSA data buffer
 * Format: level(u8) + hashedPubKey(32) + verifyRequest(bool) + [optional pubkey+sig] + legacySig(64)
 */
function parseMLDSAData(data: Uint8Array): MLDSALinkInfo | null {
  console.log('[OPNet] parseMLDSAData: data length:', data.length);
  if (data.length < 34) { // level(1) + hashedPubKey(32) + verifyRequest(1)
    console.log('[OPNet] parseMLDSAData: data too short, need at least 34 bytes');
    return null;
  }

  const reader = new BinaryReader(data);

  // Level (1 byte) - OPNet uses 0, 1, 2 for LEVEL2, LEVEL3, LEVEL5
  const levelByte = reader.readU8();
  console.log('[OPNet] parseMLDSAData: levelByte:', levelByte);
  let level: 'LEVEL2' | 'LEVEL3' | 'LEVEL5';
  switch (levelByte) {
    case 0:
      level = 'LEVEL2'; // ML-DSA-44
      break;
    case 1:
      level = 'LEVEL3'; // ML-DSA-65
      break;
    case 2:
      level = 'LEVEL5'; // ML-DSA-87
      break;
    default:
      console.log('[OPNet] parseMLDSAData: invalid level byte:', levelByte);
      return null;
  }
  console.log('[OPNet] parseMLDSAData: level:', level);

  // Hashed public key (32 bytes)
  const hashedPublicKey = toHex(reader.readBytes(32));
  console.log('[OPNet] parseMLDSAData: hashedPublicKey:', hashedPublicKey);

  // Verify request (1 byte bool)
  const verifyRequest = reader.bytesLeft() > 0 ? reader.readU8() !== 0 : false;
  console.log('[OPNet] parseMLDSAData: verifyRequest:', verifyRequest, 'remaining bytes:', reader.bytesLeft());

  // Optional: if verifyRequest is true, there's a full public key and signature
  let fullPublicKey: string | undefined;
  if (verifyRequest && reader.bytesLeft() > 2) {
    // Get public key length based on level
    const pubKeyLen = getMLDSAPublicKeyLength(level);
    const sigLen = getMLDSASignatureLength(level);
    console.log('[OPNet] parseMLDSAData: expecting pubKey:', pubKeyLen, 'sig:', sigLen);

    if (reader.bytesLeft() >= pubKeyLen + sigLen) {
      fullPublicKey = toHex(reader.readBytes(pubKeyLen));
      console.log('[OPNet] parseMLDSAData: fullPublicKey length:', fullPublicKey.length / 2);
      // Skip MLDSA signature
      reader.readBytes(sigLen);
    } else {
      console.log('[OPNet] parseMLDSAData: not enough data for full pubkey+sig');
    }
  }

  // Legacy signature (64 bytes) - optional at the end
  let legacySignature = '';
  if (reader.bytesLeft() >= 64) {
    legacySignature = toHex(reader.readBytes(64));
    console.log('[OPNet] parseMLDSAData: legacySignature:', legacySignature.substring(0, 32) + '...');
  } else {
    console.log('[OPNet] parseMLDSAData: no legacy signature, remaining:', reader.bytesLeft());
  }

  return {
    level,
    hashedPublicKey,
    fullPublicKey,
    legacySignature,
    isVerified: true,
  };
}

/**
 * Get ML-DSA public key length based on security level
 */
function getMLDSAPublicKeyLength(level: 'LEVEL2' | 'LEVEL3' | 'LEVEL5'): number {
  switch (level) {
    case 'LEVEL2': return 1312;  // ML-DSA-44
    case 'LEVEL3': return 1952;  // ML-DSA-65
    case 'LEVEL5': return 2592;  // ML-DSA-87
  }
}

/**
 * Get ML-DSA signature length based on security level
 */
function getMLDSASignatureLength(level: 'LEVEL2' | 'LEVEL3' | 'LEVEL5'): number {
  switch (level) {
    case 'LEVEL2': return 2420;  // ML-DSA-44
    case 'LEVEL3': return 3293;  // ML-DSA-65
    case 'LEVEL5': return 4595;  // ML-DSA-87
  }
}

/**
 * Helper: Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Helper: Convert Uint8Array to hex string
 */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
