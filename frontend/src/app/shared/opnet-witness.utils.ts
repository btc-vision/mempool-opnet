/**
 * OPNet Witness Data Parsing Utilities
 * Parses MLDSA/BIP360 and other feature data from raw transaction witness
 *
 * Based on OPNet transaction structure:
 * - Header: prefix(1) + flags(3) + priorityFee(8) = 12 bytes
 * - Features: encoded with length prefixes after header
 * - Feature order by priority: ACCESS_LIST, EPOCH_SUBMISSION, MLDSA_LINK_PUBKEY
 */

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
 *
 * Script structure:
 * - PUSHDATA header (12 bytes)
 * - OP_TOALTSTACK
 * - PUSHDATA minerMLDSAPublicKey (32 bytes)
 * - OP_TOALTSTACK
 * - PUSHDATA preimage/solution
 * - OP_TOALTSTACK
 * - PUSHDATA features data (length-prefixed features)
 */
export function parseOPNetFeaturesFromWitness(witness: string[]): OPNetFeatures | null {
  if (!witness || witness.length < 4) {
    return null;
  }

  try {
    const script = witness[3];
    if (!script) {
      return null;
    }

    const bytes = hexToBytes(script);
    let offset = 0;

    // Parse header push data
    const headerResult = readPushData(bytes, offset);
    if (!headerResult || headerResult.data.length !== OPNET_HEADER_LENGTH) {
      return null;
    }
    offset = headerResult.newOffset;

    const header = headerResult.data;

    // Parse header: prefix(1) + flags(3 big-endian) + priorityFee(8)
    const prefix = header[0];
    if (prefix !== 0x02 && prefix !== 0x03) {
      return null; // Invalid public key prefix
    }

    // Flags are bytes 1-3, read as big-endian 24-bit integer
    const flags = (header[1] << 16) | (header[2] << 8) | header[3];

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
    const data = epochFeature.data;
    if (data.length < 64) {
      return null;
    }

    const minerPublicKey = toHex(data.slice(0, 32));
    const salt = toHex(data.slice(32, 64));

    // Graffiti is optional - remaining bytes after 64
    let graffiti: string | undefined;
    let graffitiHex: string | undefined;
    if (data.length > 64) {
      // Read graffiti with length prefix
      let offset = 64;
      const graffitiLen = data[offset++];
      if (graffitiLen > 0 && offset + graffitiLen <= data.length) {
        const graffitiBytes = data.slice(offset, offset + graffitiLen);
        graffitiHex = toHex(graffitiBytes);
        try {
          graffiti = new TextDecoder().decode(graffitiBytes);
        } catch {
          graffiti = undefined;
        }
      }
    }

    // Calculate epoch number from block height (2016 blocks per epoch)
    const epochNumber = blockHeight ? Math.floor(blockHeight / 2016).toString() : '0';

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

    // Check if MLDSA link flag is set
    if (!(parsed.flags & FEATURE_MLDSA_LINK)) {
      return null;
    }

    // Decode features in priority order
    const features = decodeFeaturesData(parsed.flags, parsed.featuresData);
    const mldsaFeature = features.find(f => f.type === 'mldsa');

    if (!mldsaFeature || !mldsaFeature.data) {
      return null;
    }

    return parseMLDSAData(mldsaFeature.data);
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
  let offset = 0;

  // 1. Read header (12 bytes)
  const headerResult = readPushData(bytes, offset);
  if (!headerResult || headerResult.data.length !== OPNET_HEADER_LENGTH) {
    return null;
  }
  offset = headerResult.newOffset;
  const header = headerResult.data;

  // Check OP_TOALTSTACK
  if (bytes[offset++] !== OP_TOALTSTACK) {
    return null;
  }

  // 2. Read minerMLDSAPublicKey (32 bytes)
  const minerKeyResult = readPushData(bytes, offset);
  if (!minerKeyResult || minerKeyResult.data.length !== 32) {
    return null;
  }
  offset = minerKeyResult.newOffset;
  const minerMLDSAPublicKey = minerKeyResult.data;

  // Check OP_TOALTSTACK
  if (bytes[offset++] !== OP_TOALTSTACK) {
    return null;
  }

  // 3. Read preimage/solution
  const preimageResult = readPushData(bytes, offset);
  if (!preimageResult) {
    return null;
  }
  offset = preimageResult.newOffset;
  const preimage = preimageResult.data;

  // Check OP_TOALTSTACK
  if (bytes[offset++] !== OP_TOALTSTACK) {
    return null;
  }

  // Parse flags from header
  const flags = (header[1] << 16) | (header[2] << 8) | header[3];

  // 4. Read features data (if any flags are set)
  let featuresData: Uint8Array | null = null;
  if (flags !== 0 && offset < bytes.length) {
    const featuresResult = readPushData(bytes, offset);
    if (featuresResult) {
      featuresData = featuresResult.data;
    }
  }

  return {
    header,
    flags,
    minerMLDSAPublicKey,
    preimage,
    featuresData,
  };
}

interface DecodedFeature {
  type: 'accessList' | 'epoch' | 'mldsa';
  data: Uint8Array;
}

/**
 * Decode features data based on flags
 * Features are stored with length prefixes and decoded in priority order:
 * 1. ACCESS_LIST
 * 2. EPOCH_SUBMISSION
 * 3. MLDSA_LINK_PUBKEY
 */
function decodeFeaturesData(flags: number, data: Uint8Array): DecodedFeature[] {
  const features: DecodedFeature[] = [];
  let offset = 0;

  // Decode in priority order
  const featureOrder: Array<{ flag: number; type: DecodedFeature['type'] }> = [
    { flag: FEATURE_ACCESS_LIST, type: 'accessList' },
    { flag: FEATURE_EPOCH_SUBMISSION, type: 'epoch' },
    { flag: FEATURE_MLDSA_LINK, type: 'mldsa' },
  ];

  for (const { flag, type } of featureOrder) {
    if (flags & flag) {
      // Read length-prefixed data
      const lenResult = readVarInt(data, offset);
      if (lenResult.value > 0 && offset + lenResult.size + lenResult.value <= data.length) {
        offset += lenResult.size;
        features.push({
          type,
          data: data.slice(offset, offset + lenResult.value),
        });
        offset += lenResult.value;
      }
    }
  }

  return features;
}

/**
 * Parse MLDSA data buffer
 * Format: level(u8) + hashedPubKey(32) + verifyRequest(bool) + [optional pubkey+sig] + legacySig(64)
 */
function parseMLDSAData(data: Uint8Array): MLDSALinkInfo | null {
  if (data.length < 34) { // level(1) + hashedPubKey(32) + verifyRequest(1)
    return null;
  }

  let offset = 0;

  // Level (1 byte) - OPNet uses 0, 1, 2 for LEVEL2, LEVEL3, LEVEL5
  const levelByte = data[offset++];
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
      return null;
  }

  // Hashed public key (32 bytes)
  if (data.length < offset + 32) {
    return null;
  }
  const hashedPublicKey = toHex(data.slice(offset, offset + 32));
  offset += 32;

  // Verify request (1 byte bool)
  const verifyRequest = data.length > offset ? data[offset++] !== 0 : false;

  // Optional: if verifyRequest is true, there's a full public key and signature
  let fullPublicKey: string | undefined;
  if (verifyRequest && data.length > offset + 2) {
    // Get public key length based on level
    const pubKeyLen = getMLDSAPublicKeyLength(level);
    const sigLen = getMLDSASignatureLength(level);

    if (data.length >= offset + pubKeyLen + sigLen) {
      fullPublicKey = toHex(data.slice(offset, offset + pubKeyLen));
      offset += pubKeyLen;
      // Skip MLDSA signature
      offset += sigLen;
    }
  }

  // Legacy signature (64 bytes) - optional at the end
  let legacySignature = '';
  if (data.length >= offset + 64) {
    legacySignature = toHex(data.slice(offset, offset + 64));
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
 * Read push data from script bytes
 */
function readPushData(bytes: Uint8Array, offset: number): { data: Uint8Array; newOffset: number } | null {
  if (offset >= bytes.length) {
    return null;
  }

  const opcode = bytes[offset++];

  // OP_PUSHBYTES_1 to OP_PUSHBYTES_75
  if (opcode >= 0x01 && opcode <= 0x4b) {
    const len = opcode;
    if (offset + len > bytes.length) return null;
    return { data: bytes.slice(offset, offset + len), newOffset: offset + len };
  }
  // OP_PUSHDATA1
  else if (opcode === 0x4c) {
    if (offset >= bytes.length) return null;
    const len = bytes[offset++];
    if (offset + len > bytes.length) return null;
    return { data: bytes.slice(offset, offset + len), newOffset: offset + len };
  }
  // OP_PUSHDATA2
  else if (opcode === 0x4d) {
    if (offset + 1 >= bytes.length) return null;
    const len = bytes[offset] | (bytes[offset + 1] << 8);
    offset += 2;
    if (offset + len > bytes.length) return null;
    return { data: bytes.slice(offset, offset + len), newOffset: offset + len };
  }
  // OP_PUSHDATA4
  else if (opcode === 0x4e) {
    if (offset + 3 >= bytes.length) return null;
    const len = bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
    offset += 4;
    if (offset + len > bytes.length) return null;
    return { data: bytes.slice(offset, offset + len), newOffset: offset + len };
  }

  return null;
}

/**
 * Read varint from buffer
 */
function readVarInt(buffer: Uint8Array, offset: number): { value: number; size: number } {
  if (offset >= buffer.length) {
    return { value: 0, size: 0 };
  }

  const first = buffer[offset];
  if (first < 0xfd) {
    return { value: first, size: 1 };
  } else if (first === 0xfd && offset + 2 < buffer.length) {
    return { value: buffer[offset + 1] | (buffer[offset + 2] << 8), size: 3 };
  } else if (first === 0xfe && offset + 4 < buffer.length) {
    return {
      value: buffer[offset + 1] | (buffer[offset + 2] << 8) | (buffer[offset + 3] << 16) | (buffer[offset + 4] << 24),
      size: 5
    };
  }
  return { value: first, size: 1 };
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
