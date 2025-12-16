/**
 * OPNet Witness Data Parsing Utilities
 * Parses MLDSA/BIP360 and other feature data from raw transaction witness
 */

import { MLDSALinkInfo, OPNetFeatures, EpochSubmissionInfo } from '@interfaces/electrs.interface';

// Feature flags (from OPNet header)
const FEATURE_ACCESS_LIST = 0x01;
const FEATURE_EPOCH_SUBMISSION = 0x02;
const FEATURE_MLDSA_LINK = 0x04;

// OPNet header is 12 bytes
const OPNET_HEADER_LENGTH = 12;

/**
 * Parse OPNet features from raw witness data
 * witness[3] is the script containing the OPNet header
 * Header format (12 bytes): prefix(1) + flags(3 big-endian) + priorityFee(8)
 */
export function parseOPNetFeaturesFromWitness(witness: string[]): OPNetFeatures | null {
  if (!witness || witness.length < 4) {
    return null;
  }

  try {
    // witness[3] is the script - first we need to parse it to extract push data
    const script = witness[3];
    if (!script) {
      return null;
    }

    // Parse the script to get the header (first PUSHBYTES_12)
    const header = parseFirstPushData(script, OPNET_HEADER_LENGTH);
    if (!header || header.length < OPNET_HEADER_LENGTH) {
      return null;
    }

    // Parse header: prefix(1) + flags(3 big-endian) + priorityFee(8)
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
 * The epoch data is in the script after the header when FEATURE_EPOCH_SUBMISSION is set
 * Format: epochNumber(8 bytes LE) + solution(32) + salt(32) + graffitiLen(varint) + graffiti(variable)
 */
export function extractEpochSubmissionFromWitness(witness: string[]): EpochSubmissionInfo | null {
  if (!witness || witness.length < 4) {
    return null;
  }

  try {
    const script = witness[3];
    if (!script) {
      return null;
    }

    // Get all push data items from the script
    const pushDataItems = parseAllPushData(script);
    if (pushDataItems.length < 2) {
      return null;
    }

    // First item is the header
    const header = pushDataItems[0];
    if (!header || header.length < OPNET_HEADER_LENGTH) {
      return null;
    }

    // Parse flags
    const flags = (header[1] << 16) | (header[2] << 8) | header[3];
    if (!(flags & FEATURE_EPOCH_SUBMISSION)) {
      return null;
    }

    // Epoch submission data comes after header
    // It's typically in pushDataItems[1] if no access list, or later if access list present
    let dataIndex = 1;
    if (flags & FEATURE_ACCESS_LIST) {
      dataIndex++; // Skip access list data
    }

    // Look for epoch submission data - should be at least 72 bytes (8 + 32 + 32)
    for (let i = dataIndex; i < pushDataItems.length; i++) {
      const item = pushDataItems[i];
      if (item.length >= 72) {
        const parsed = parseEpochSubmissionData(item);
        if (parsed) {
          return parsed;
        }
      }
    }

    return null;
  } catch (e) {
    console.warn('[OPNet] Failed to extract epoch submission from witness:', e);
    return null;
  }
}

/**
 * Parse epoch submission data buffer
 * Format: epochNumber(8 bytes LE) + solution(32) + salt(32) + graffitiLen(varint) + graffiti(variable)
 */
function parseEpochSubmissionData(data: Uint8Array): EpochSubmissionInfo | null {
  if (data.length < 72) { // 8 + 32 + 32 minimum
    return null;
  }

  let offset = 0;

  // Epoch number (8 bytes, little-endian)
  const epochLow = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
  const epochHigh = data[offset + 4] | (data[offset + 5] << 8) | (data[offset + 6] << 16) | (data[offset + 7] << 24);
  // Combine as BigInt for large epoch numbers
  const epochNumber = BigInt(epochLow) + (BigInt(epochHigh) << 32n);
  offset += 8;

  // Solution hash (32 bytes)
  const solution = toHex(data.slice(offset, offset + 32));
  offset += 32;

  // Salt (32 bytes)
  const salt = toHex(data.slice(offset, offset + 32));
  offset += 32;

  // Graffiti (variable length with varint prefix)
  let graffiti: string | undefined;
  let graffitiHex: string | undefined;
  if (data.length > offset) {
    const graffitiLen = readVarInt(data, offset);
    offset += varIntSize(graffitiLen);
    if (graffitiLen > 0 && data.length >= offset + graffitiLen) {
      const graffitiBytes = data.slice(offset, offset + graffitiLen);
      graffitiHex = toHex(graffitiBytes);
      try {
        graffiti = new TextDecoder().decode(graffitiBytes);
      } catch {
        graffiti = undefined;
      }
    }
  }

  return {
    epochNumber: epochNumber.toString(),
    minerPublicKey: '', // Will be populated from transaction sender
    solution,
    salt,
    graffiti,
    graffitiHex,
    signature: '',
  };
}

/**
 * Extract MLDSA/BIP360 link info from witness data
 * The MLDSA data is in the script after the header, following other features
 * Format: level(u8) + hashedPubKey(32) + verifyRequest(bool) + [optional] + legacySig(64)
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

    // Get all push data items from the script
    const pushDataItems = parseAllPushData(script);
    if (pushDataItems.length < 2) {
      return null;
    }

    // First item is the header
    const header = pushDataItems[0];
    if (!header || header.length < OPNET_HEADER_LENGTH) {
      return null;
    }

    // Parse flags
    const flags = (header[1] << 16) | (header[2] << 8) | header[3];
    if (!(flags & FEATURE_MLDSA_LINK)) {
      return null;
    }

    // Find MLDSA data - it comes after header and any other features
    // Features are in order: ACCESS_LIST, EPOCH_SUBMISSION, MLDSA_LINK
    let dataIndex = 1; // Start after header

    // The MLDSA data should be one of the push data items
    // We need to find the one that contains level + hashedPubKey format
    // Try to find it by checking for valid MLDSA level bytes (2, 3, or 5)
    for (let i = dataIndex; i < pushDataItems.length; i++) {
      const item = pushDataItems[i];
      if (item.length >= 34) { // At minimum: level(1) + hashedPubKey(32) + verifyRequest(1)
        const levelByte = item[0];
        if (levelByte === 2 || levelByte === 3 || levelByte === 5) {
          // This looks like MLDSA data
          return parseMLDSAData(item);
        }
      }
    }

    // Alternative: The MLDSA data might be in OP_PUSHDATA sections
    // Try to find it in the raw script by looking for the pattern
    const mldsaData = findMLDSADataInScript(script);
    if (mldsaData) {
      return parseMLDSAData(mldsaData);
    }

    return null;
  } catch (e) {
    console.warn('[OPNet] Failed to extract MLDSA from witness:', e);
    return null;
  }
}

/**
 * Parse MLDSA data buffer
 * Format: level(u8) + hashedPubKey(32) + verifyRequest(bool) + [optional pubkey+sig] + legacySig(64)
 */
function parseMLDSAData(data: Uint8Array): MLDSALinkInfo | null {
  if (data.length < 34) {
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
    // Public key with length prefix
    const pubKeyLen = readVarInt(data, offset);
    offset += varIntSize(pubKeyLen);
    if (data.length >= offset + pubKeyLen) {
      fullPublicKey = toHex(data.slice(offset, offset + pubKeyLen));
      offset += pubKeyLen;

      // MLDSA signature with length prefix (skip it)
      if (data.length > offset) {
        const sigLen = readVarInt(data, offset);
        offset += varIntSize(sigLen);
        offset += sigLen;
      }
    }
  }

  // Legacy signature (64 bytes) - optional
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
 * Parse first push data of given length from script hex
 */
function parseFirstPushData(scriptHex: string, expectedLength: number): Uint8Array | null {
  const bytes = hexToBytes(scriptHex);
  let offset = 0;

  while (offset < bytes.length) {
    const opcode = bytes[offset++];

    // OP_PUSHBYTES_1 to OP_PUSHBYTES_75
    if (opcode >= 0x01 && opcode <= 0x4b) {
      const len = opcode;
      if (len === expectedLength && offset + len <= bytes.length) {
        return bytes.slice(offset, offset + len);
      }
      offset += len;
    }
    // OP_PUSHDATA1
    else if (opcode === 0x4c) {
      if (offset >= bytes.length) break;
      const len = bytes[offset++];
      if (len === expectedLength && offset + len <= bytes.length) {
        return bytes.slice(offset, offset + len);
      }
      offset += len;
    }
    // OP_PUSHDATA2
    else if (opcode === 0x4d) {
      if (offset + 1 >= bytes.length) break;
      const len = bytes[offset] | (bytes[offset + 1] << 8);
      offset += 2;
      if (len === expectedLength && offset + len <= bytes.length) {
        return bytes.slice(offset, offset + len);
      }
      offset += len;
    }
    // Other opcodes - skip
    else {
      continue;
    }
  }

  return null;
}

/**
 * Parse all push data items from script hex
 */
function parseAllPushData(scriptHex: string): Uint8Array[] {
  const bytes = hexToBytes(scriptHex);
  const items: Uint8Array[] = [];
  let offset = 0;

  while (offset < bytes.length) {
    const opcode = bytes[offset++];

    // OP_PUSHBYTES_1 to OP_PUSHBYTES_75
    if (opcode >= 0x01 && opcode <= 0x4b) {
      const len = opcode;
      if (offset + len <= bytes.length) {
        items.push(bytes.slice(offset, offset + len));
      }
      offset += len;
    }
    // OP_PUSHDATA1
    else if (opcode === 0x4c) {
      if (offset >= bytes.length) break;
      const len = bytes[offset++];
      if (offset + len <= bytes.length) {
        items.push(bytes.slice(offset, offset + len));
      }
      offset += len;
    }
    // OP_PUSHDATA2
    else if (opcode === 0x4d) {
      if (offset + 1 >= bytes.length) break;
      const len = bytes[offset] | (bytes[offset + 1] << 8);
      offset += 2;
      if (offset + len <= bytes.length) {
        items.push(bytes.slice(offset, offset + len));
      }
      offset += len;
    }
    // OP_PUSHDATA4
    else if (opcode === 0x4e) {
      if (offset + 3 >= bytes.length) break;
      const len = bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
      offset += 4;
      if (offset + len <= bytes.length) {
        items.push(bytes.slice(offset, offset + len));
      }
      offset += len;
    }
  }

  return items;
}

/**
 * Try to find MLDSA data pattern in script
 * Look for: level byte (2/3/5) followed by 32+ bytes
 */
function findMLDSADataInScript(scriptHex: string): Uint8Array | null {
  const bytes = hexToBytes(scriptHex);

  // Look for MLDSA level bytes followed by enough data
  for (let i = 0; i < bytes.length - 34; i++) {
    const b = bytes[i];
    // Check if this could be a level byte at start of pushed data
    if ((b === 2 || b === 3 || b === 5)) {
      // Check if preceded by a push opcode
      if (i > 0) {
        const prevByte = bytes[i - 1];
        // Check various push opcode scenarios
        if ((prevByte >= 34 && prevByte <= 0x4b) || // OP_PUSHBYTES_N
            (i > 1 && bytes[i - 2] === 0x4c && prevByte >= 34)) { // OP_PUSHDATA1
          // This looks like MLDSA data
          const len = Math.min(bytes.length - i, 200); // Reasonable max
          return bytes.slice(i, i + len);
        }
      }
    }
  }

  return null;
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

/**
 * Read varint from buffer
 */
function readVarInt(buffer: Uint8Array, offset: number): number {
  const first = buffer[offset];
  if (first < 0xfd) {
    return first;
  } else if (first === 0xfd) {
    return buffer[offset + 1] | (buffer[offset + 2] << 8);
  } else if (first === 0xfe) {
    return buffer[offset + 1] | (buffer[offset + 2] << 8) | (buffer[offset + 3] << 16) | (buffer[offset + 4] << 24);
  }
  return buffer[offset + 1] | (buffer[offset + 2] << 8) | (buffer[offset + 3] << 16) | (buffer[offset + 4] << 24);
}

/**
 * Get varint size
 */
function varIntSize(value: number): number {
  if (value < 0xfd) return 1;
  if (value <= 0xffff) return 3;
  if (value <= 0xffffffff) return 5;
  return 9;
}
