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
    let offset = 0;

    // Parse header push data
    const headerResult = readPushData(bytes, offset);
    if (!headerResult || headerResult.data.length !== OPNET_HEADER_LENGTH) {
      console.log('[OPNet] parseFeatures: header invalid, length:', headerResult?.data?.length, 'expected:', OPNET_HEADER_LENGTH);
      return null;
    }
    offset = headerResult.newOffset;

    const header = headerResult.data;
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
  let offset = 0;
  console.log('[OPNet] parseScript: total bytes:', bytes.length);

  // 1. Read header (12 bytes)
  const headerResult = readPushData(bytes, offset);
  if (!headerResult || headerResult.data.length !== OPNET_HEADER_LENGTH) {
    console.log('[OPNet] parseScript: header read failed, got length:', headerResult?.data?.length);
    return null;
  }
  offset = headerResult.newOffset;
  const header = headerResult.data;
  console.log('[OPNet] parseScript: header:', toHex(header), 'offset now:', offset);

  // Check OP_TOALTSTACK
  if (bytes[offset] !== OP_TOALTSTACK) {
    console.log('[OPNet] parseScript: expected OP_TOALTSTACK (0x6b) at', offset, 'got:', bytes[offset]?.toString(16));
    return null;
  }
  offset++;

  // 2. Read minerMLDSAPublicKey (32 bytes)
  const minerKeyResult = readPushData(bytes, offset);
  if (!minerKeyResult || minerKeyResult.data.length !== 32) {
    console.log('[OPNet] parseScript: minerKey read failed, got length:', minerKeyResult?.data?.length);
    return null;
  }
  offset = minerKeyResult.newOffset;
  const minerMLDSAPublicKey = minerKeyResult.data;
  console.log('[OPNet] parseScript: minerKey:', toHex(minerMLDSAPublicKey), 'offset now:', offset);

  // Check OP_TOALTSTACK
  if (bytes[offset] !== OP_TOALTSTACK) {
    console.log('[OPNet] parseScript: expected OP_TOALTSTACK at', offset, 'got:', bytes[offset]?.toString(16));
    return null;
  }
  offset++;

  // 3. Read preimage/solution
  const preimageResult = readPushData(bytes, offset);
  if (!preimageResult) {
    console.log('[OPNet] parseScript: preimage read failed at offset:', offset);
    return null;
  }
  offset = preimageResult.newOffset;
  const preimage = preimageResult.data;
  console.log('[OPNet] parseScript: preimage length:', preimage.length, 'offset now:', offset);

  // Check OP_TOALTSTACK
  if (bytes[offset] !== OP_TOALTSTACK) {
    console.log('[OPNet] parseScript: expected OP_TOALTSTACK at', offset, 'got:', bytes[offset]?.toString(16));
    return null;
  }
  offset++;

  // Parse flags from header
  const flags = (header[1] << 16) | (header[2] << 8) | header[3];
  console.log('[OPNet] parseScript: flags:', flags, 'binary:', flags.toString(2));

  // 4. Read features data (if any flags are set)
  let featuresData: Uint8Array | null = null;
  if (flags !== 0 && offset < bytes.length) {
    console.log('[OPNet] parseScript: reading features data at offset:', offset, 'remaining bytes:', bytes.length - offset);
    const featuresResult = readPushData(bytes, offset);
    if (featuresResult) {
      featuresData = featuresResult.data;
      console.log('[OPNet] parseScript: features data length:', featuresData.length, 'hex:', toHex(featuresData.slice(0, 100)));
    } else {
      console.log('[OPNet] parseScript: features read failed');
    }
  } else {
    console.log('[OPNet] parseScript: no features data (flags:', flags, 'offset:', offset, 'length:', bytes.length, ')');
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
  console.log('[OPNet] decodeFeatures: flags:', flags, 'data length:', data.length);

  // Decode in priority order
  const featureOrder: Array<{ flag: number; type: DecodedFeature['type'] }> = [
    { flag: FEATURE_ACCESS_LIST, type: 'accessList' },
    { flag: FEATURE_EPOCH_SUBMISSION, type: 'epoch' },
    { flag: FEATURE_MLDSA_LINK, type: 'mldsa' },
  ];

  for (const { flag, type } of featureOrder) {
    if (flags & flag) {
      console.log('[OPNet] decodeFeatures: reading', type, 'at offset:', offset);
      // Read length-prefixed data
      const lenResult = readVarInt(data, offset);
      console.log('[OPNet] decodeFeatures:', type, 'varint:', lenResult.value, 'size:', lenResult.size);
      if (lenResult.value > 0 && offset + lenResult.size + lenResult.value <= data.length) {
        offset += lenResult.size;
        const featureData = data.slice(offset, offset + lenResult.value);
        console.log('[OPNet] decodeFeatures:', type, 'data length:', featureData.length);
        features.push({
          type,
          data: featureData,
        });
        offset += lenResult.value;
      } else {
        console.log('[OPNet] decodeFeatures:', type, 'invalid length or bounds');
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
