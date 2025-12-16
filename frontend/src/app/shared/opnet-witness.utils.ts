/**
 * OPNet Witness Data Parsing Utilities
 * Parses MLDSA/BIP360 and other feature data from raw transaction witness
 *
 * Uses @btc-vision/bitcoin script.decompile() to properly parse witness scripts
 * matching the OPNet node implementation.
 */
import { Buffer } from 'buffer';
import { script, opcodes } from '@btc-vision/bitcoin';
import { BinaryReader } from '@btc-vision/transaction';
import * as pako from 'pako';

// Feature flags from @btc-vision/transaction Features enum
const Features = {
    ACCESS_LIST: 0b1,
    EPOCH_SUBMISSION: 0b10,
    MLDSA_LINK_PUBKEY: 0b100,
} as const;

// Feature priority order for decoding (matches FeaturePriority enum)
const FeaturePriority = {
    ACCESS_LIST: 1,
    EPOCH_SUBMISSION: 2,
    MLDSA_LINK_PUBKEY: 3,
} as const;

// ML-DSA security levels (matching @btc-vision/bip32 MLDSASecurityLevel enum)
// Values are the ML-DSA algorithm numbers: 44, 65, 87
const MLDSASecurityLevel = {
    LEVEL2: 44,  // ML-DSA-44
    LEVEL3: 65,  // ML-DSA-65
    LEVEL5: 87,  // ML-DSA-87
} as const;

// ML-DSA public key lengths by level
const MLDSA_PUBLIC_KEY_LENGTHS: Record<number, number> = {
    [MLDSASecurityLevel.LEVEL2]: 1312,  // ML-DSA-44
    [MLDSASecurityLevel.LEVEL3]: 1952,  // ML-DSA-65
    [MLDSASecurityLevel.LEVEL5]: 2592,  // ML-DSA-87
};

// ML-DSA signature lengths by level
const MLDSA_SIGNATURE_LENGTHS: Record<number, number> = {
    [MLDSASecurityLevel.LEVEL2]: 2420,  // ML-DSA-44
    [MLDSASecurityLevel.LEVEL3]: 3293,  // ML-DSA-65
    [MLDSASecurityLevel.LEVEL5]: 4595,  // ML-DSA-87
};

// Expected header length: prefix(1) + flags(3) + priorityFee(8) = 12 bytes
const OPNET_HEADER_LENGTH = 12;

// OPNet magic bytes "op" = 0x6f70
const OPNET_MAGIC = Buffer.from('op', 'utf-8');

export interface OPNetFeatures {
    hasAccessList: boolean;
    hasEpochSubmission: boolean;
    hasMLDSALink: boolean;
    featureFlags: number;
}

export interface EpochSubmissionInfo {
    epochNumber: string;
    minerPublicKey: string;
    solution: string;
    salt: string;
    graffiti?: string;
    graffitiHex?: string;
    signature: string;
}

export interface MLDSALinkInfo {
    level: 'LEVEL2' | 'LEVEL3' | 'LEVEL5';
    hashedPublicKey: string;
    fullPublicKey?: string;
    legacySignature: string;
    isVerified: boolean;
    verifyRequest: boolean;
}

interface DecodedFeature {
    type: 'accessList' | 'epoch' | 'mldsa';
    data: Buffer;
}

/**
 * Parsed OPNet script structure
 */
interface ParsedOPNetScript {
    flags: number;
    priorityFeeSat: bigint;
    publicKeyPrefix: number;
    minerMLDSAPublicKey: Buffer;
    solution: Buffer;
    featuresData: Buffer | null;
}

/**
 * Try to decompress gzip data, return original if not compressed
 */
function tryDecompress(data: Buffer): Buffer {
    // Check for gzip magic bytes (0x1f 0x8b)
    if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b) {
        try {
            console.log('[OPNet] tryDecompress: found gzip magic, decompressing...');
            const decompressed = pako.ungzip(data);
            console.log('[OPNet] tryDecompress: decompressed', data.length, '->', decompressed.length, 'bytes');
            return Buffer.from(decompressed);
        } catch (e) {
            console.log('[OPNet] tryDecompress: gzip decompress failed:', e);
            return data;
        }
    }

    // Try raw inflate (deflate without gzip header)
    try {
        const inflated = pako.inflate(data);
        if (inflated.length > data.length) {
            console.log('[OPNet] tryDecompress: raw inflate succeeded', data.length, '->', inflated.length, 'bytes');
            return Buffer.from(inflated);
        }
    } catch {
        // Not compressed or different format
    }

    return data;
}

/**
 * Decompile and parse the OPNet script from witness[3]
 *
 * Script structure (CalldataGenerator):
 * 1. Header (12 bytes) - prefix(1) + flags(3) + priorityFee(8)
 * 2. OP_TOALTSTACK
 * 3. challenge.publicKey (32 bytes) - minerMLDSAPublicKey
 * 4. OP_TOALTSTACK
 * 5. challenge.solution
 * 6. OP_TOALTSTACK
 * 7. ... verification opcodes ...
 * 8. OP_IF
 * 9. MAGIC ("op")
 * 10. **featuresData chunks** (what we want)
 * 11. OP_1NEGATE
 * 12. ...calldata chunks
 * 13. OP_ELSE, OP_1, OP_ENDIF
 */
function parseOPNetScript(rawScriptHex: string): ParsedOPNetScript | null {
    const rawScriptBuf = Buffer.from(rawScriptHex, 'hex');

    let decodedScript: (number | Buffer)[] | null;
    try {
        decodedScript = script.decompile(rawScriptBuf);
    } catch {
        console.log('[OPNet] parseScript: failed to decompile script');
        return null;
    }

    if (!decodedScript || decodedScript.length === 0) {
        console.log('[OPNet] parseScript: decompiled script is empty');
        return null;
    }

    // Create a mutable copy
    const scriptElements: (number | Buffer)[] = [...decodedScript];

    // 1. Read header (12 bytes)
    const header = scriptElements.shift();
    if (!Buffer.isBuffer(header) || header.length !== OPNET_HEADER_LENGTH) {
        console.log('[OPNet] parseScript: invalid header, got length:', Buffer.isBuffer(header) ? header.length : 'not a buffer');
        return null;
    }

    // Parse header
    const headerReader = new BinaryReader(header);
    const headerBytes = headerReader.readBytes(4);
    const priorityFeeSat = headerReader.readU64();

    const publicKeyPrefix = headerBytes[0];
    if (publicKeyPrefix !== 0x02 && publicKeyPrefix !== 0x03) {
        console.log('[OPNet] parseScript: invalid public key prefix:', publicKeyPrefix);
        return null;
    }

    const flagBuffer = Buffer.from(headerBytes.slice(1));
    const flags = flagBuffer.readUIntBE(0, 3);

    // 2. Expect OP_TOALTSTACK
    if (scriptElements.shift() !== opcodes.OP_TOALTSTACK) {
        console.log('[OPNet] parseScript: expected OP_TOALTSTACK after header');
        return null;
    }

    // 3. Read minerMLDSAPublicKey (32 bytes)
    const minerMLDSAPublicKey = scriptElements.shift();
    if (!Buffer.isBuffer(minerMLDSAPublicKey) || minerMLDSAPublicKey.length !== 32) {
        console.log('[OPNet] parseScript: invalid minerMLDSAPublicKey');
        return null;
    }

    // 4. Expect OP_TOALTSTACK
    if (scriptElements.shift() !== opcodes.OP_TOALTSTACK) {
        console.log('[OPNet] parseScript: expected OP_TOALTSTACK after minerMLDSAPublicKey');
        return null;
    }

    // 5. Read solution (variable length)
    const solution = scriptElements.shift();
    if (!Buffer.isBuffer(solution)) {
        console.log('[OPNet] parseScript: invalid solution');
        return null;
    }

    // 6. Expect OP_TOALTSTACK
    if (scriptElements.shift() !== opcodes.OP_TOALTSTACK) {
        console.log('[OPNet] parseScript: expected OP_TOALTSTACK after solution');
        return null;
    }

    // Now we need to find the MAGIC "op" and extract features data after it
    let featuresData: Buffer | null = null;

    if (flags !== 0) {
        // Find the MAGIC "op" in the remaining script
        let magicIndex = -1;
        for (let i = 0; i < scriptElements.length; i++) {
            const elem = scriptElements[i];
            if (Buffer.isBuffer(elem) && elem.equals(OPNET_MAGIC)) {
                magicIndex = i;
                break;
            }
        }

        if (magicIndex !== -1) {
            // Collect all buffers after MAGIC until we hit OP_1NEGATE
            const featureBuffers: Buffer[] = [];
            for (let i = magicIndex + 1; i < scriptElements.length; i++) {
                const elem = scriptElements[i];
                if (elem === opcodes.OP_1NEGATE) {
                    break;
                }
                if (Buffer.isBuffer(elem)) {
                    featureBuffers.push(elem);
                }
            }

            if (featureBuffers.length > 0) {
                featuresData = Buffer.concat(featureBuffers);
                console.log('[OPNet] parseScript: extracted features data:', featuresData.length, 'bytes from', featureBuffers.length, 'chunks');
            }
        } else {
            console.log('[OPNet] parseScript: MAGIC "op" not found, flags:', flags);
        }
    }

    return {
        flags,
        priorityFeeSat,
        publicKeyPrefix,
        minerMLDSAPublicKey: Buffer.from(minerMLDSAPublicKey),
        solution: Buffer.from(solution),
        featuresData,
    };
}

/**
 * Decode features data based on priority order
 *
 * Each feature is encoded with writeBytesWithLength() (U32 BE length prefix)
 * Features are sorted by priority: ACCESS_LIST(1) < EPOCH_SUBMISSION(2) < MLDSA_LINK_PUBKEY(3)
 */
function decodeFeaturesData(flags: number, data: Buffer): DecodedFeature[] {
    const features: DecodedFeature[] = [];

    console.log('[OPNet] decodeFeaturesData: flags:', flags, 'dataLen:', data.length);
    console.log('[OPNet] decodeFeaturesData: first 32 bytes:', data.subarray(0, 32).toString('hex'));

    // Determine enabled features sorted by priority
    const enabledFeatures: Array<{ flag: number; type: DecodedFeature['type']; priority: number }> = [];

    if ((flags & Features.ACCESS_LIST) === Features.ACCESS_LIST) {
        enabledFeatures.push({ flag: Features.ACCESS_LIST, type: 'accessList', priority: FeaturePriority.ACCESS_LIST });
    }
    if ((flags & Features.EPOCH_SUBMISSION) === Features.EPOCH_SUBMISSION) {
        enabledFeatures.push({ flag: Features.EPOCH_SUBMISSION, type: 'epoch', priority: FeaturePriority.EPOCH_SUBMISSION });
    }
    if ((flags & Features.MLDSA_LINK_PUBKEY) === Features.MLDSA_LINK_PUBKEY) {
        enabledFeatures.push({ flag: Features.MLDSA_LINK_PUBKEY, type: 'mldsa', priority: FeaturePriority.MLDSA_LINK_PUBKEY });
    }

    // Sort by priority (ascending)
    enabledFeatures.sort((a, b) => a.priority - b.priority);
    console.log('[OPNet] decodeFeaturesData: enabledFeatures:', enabledFeatures.map(f => f.type));

    // Read features with length prefixes
    const reader = new BinaryReader(data);

    for (const { type } of enabledFeatures) {
        if (reader.bytesLeft() < 4) {
            console.log('[OPNet] decodeFeaturesData: not enough bytes for length prefix of', type, 'bytesLeft:', reader.bytesLeft());
            break;
        }

        try {
            const featureData = Buffer.from(reader.readBytesWithLength());
            console.log('[OPNet] decodeFeaturesData: read', type, 'length:', featureData.length);

            // ACCESS_LIST is compressed, others are not
            if (type === 'accessList') {
                const decompressed = tryDecompress(featureData);
                features.push({ type, data: decompressed });
            } else {
                features.push({ type, data: featureData });
            }
        } catch (e) {
            console.log(`[OPNet] decodeFeaturesData: failed to read ${type}:`, e);
            break;
        }
    }

    return features;
}

/**
 * Parse OPNet features from raw witness data
 * witness[3] is the script containing the OPNet data
 */
export function parseOPNetFeaturesFromWitness(witness: string[]): OPNetFeatures | null {
    if (!witness || witness.length < 4) {
        return null;
    }

    try {
        const rawScript = witness[3];
        if (!rawScript) {
            return null;
        }

        const parsed = parseOPNetScript(rawScript);
        if (!parsed) {
            return null;
        }

        return {
            hasAccessList: (parsed.flags & Features.ACCESS_LIST) === Features.ACCESS_LIST,
            hasEpochSubmission: (parsed.flags & Features.EPOCH_SUBMISSION) === Features.EPOCH_SUBMISSION,
            hasMLDSALink: (parsed.flags & Features.MLDSA_LINK_PUBKEY) === Features.MLDSA_LINK_PUBKEY,
            featureFlags: parsed.flags,
        };
    } catch (e) {
        console.warn('[OPNet] Failed to parse features from witness:', e);
        return null;
    }
}

/**
 * Extract Epoch Submission info from witness data
 *
 * Epoch data format (from encodeChallengeSubmission):
 * - publicKey: 32 bytes (miner's public key hash)
 * - solution: variable (from challenge, already in header)
 * - graffiti: optional with length prefix
 *
 * Wait - looking at the code again:
 * writer.writeBytes(feature.data.publicKey.toBuffer()); // 32 bytes
 * writer.writeBytes(feature.data.solution);  // This is NOT in the feature data, it's the challenge.solution
 *
 * Actually the epoch feature data is:
 * - publicKey (32 bytes)
 * - solution (the actual PoW solution, separate from header solution)
 * - graffiti (optional with length prefix)
 */
export function extractEpochSubmissionFromWitness(witness: string[], blockHeight?: number): EpochSubmissionInfo | null {
    if (!witness || witness.length < 4) {
        return null;
    }

    try {
        const rawScript = witness[3];
        if (!rawScript) {
            return null;
        }

        const parsed = parseOPNetScript(rawScript);
        if (!parsed || !parsed.featuresData) {
            return null;
        }

        if ((parsed.flags & Features.EPOCH_SUBMISSION) !== Features.EPOCH_SUBMISSION) {
            return null;
        }

        const features = decodeFeaturesData(parsed.flags, parsed.featuresData);
        const epochFeature = features.find(f => f.type === 'epoch');

        if (!epochFeature || !epochFeature.data) {
            return null;
        }

        const data = epochFeature.data;
        console.log('[OPNet] extractEpochSubmission: data length:', data.length);

        // Epoch submission format:
        // - publicKey: 32 bytes (SHA256 hash of ML-DSA public key)
        // - solution: 20 bytes (SHA-1 hash)
        // - graffiti: optional with U32 length prefix
        if (data.length < 52) {
            console.log('[OPNet] extractEpochSubmission: data too short, need at least 52 bytes (32 + 20)');
            return null;
        }

        const reader = new BinaryReader(data);

        // Read miner public key (32 bytes - SHA256 hash of ML-DSA public key)
        const mldsaPublicKey = Buffer.from(reader.readBytes(32));

        // Read solution (20 bytes - SHA-1 hash)
        const epochSolution = Buffer.from(reader.readBytes(20));

        let graffiti: string | undefined;
        let graffitiHex: string | undefined;

        // Graffiti is optional with length prefix
        if (reader.bytesLeft() > 0) {
            try {
                const graffitiBytes = Buffer.from(reader.readBytesWithLength());
                if (graffitiBytes.length > 0) {
                    graffitiHex = graffitiBytes.toString('hex');
                    try {
                        graffiti = graffitiBytes.toString('utf-8');
                    } catch {
                        graffiti = undefined;
                    }
                }
            } catch {
                // No graffiti or invalid format
            }
        }

        // Calculate epoch number from block height (5 blocks per epoch)
        // Submissions are for epoch + 2 (you submit for 2 epochs ahead)
        const currentEpoch = blockHeight !== undefined ? Math.floor(blockHeight / 5) : 0;
        const submissionEpoch = currentEpoch + 2;
        const epochNumber = submissionEpoch.toString();

        return {
            epochNumber,
            minerPublicKey: mldsaPublicKey.toString('hex'),
            solution: epochSolution.toString('hex'),
            salt: parsed.solution.toString('hex'), // The solution from header is the salt/preimage
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
 *
 * MLDSA data format (from encodeLinkRequest):
 * - level: U8 (0=LEVEL2, 1=LEVEL3, 2=LEVEL5)
 * - hashedPublicKey: 32 bytes
 * - verifyRequest: boolean (1 byte)
 * - if verifyRequest:
 *   - publicKey: 1312/1952/2592 bytes based on level
 *   - mldsaSignature: 2420/3293/4595 bytes based on level
 * - legacySignature: 64 bytes (Schnorr)
 */
export function extractMLDSAFromWitness(witness: string[]): MLDSALinkInfo | null {
    if (!witness || witness.length < 4) {
        console.log('[OPNet] extractMLDSA: witness too short');
        return null;
    }

    try {
        const rawScript = witness[3];
        if (!rawScript) {
            console.log('[OPNet] extractMLDSA: witness[3] is empty');
            return null;
        }

        const parsed = parseOPNetScript(rawScript);
        if (!parsed) {
            console.log('[OPNet] extractMLDSA: parseOPNetScript returned null');
            return null;
        }

        if ((parsed.flags & Features.MLDSA_LINK_PUBKEY) !== Features.MLDSA_LINK_PUBKEY) {
            console.log('[OPNet] extractMLDSA: MLDSA flag not set, flags:', parsed.flags);
            return null;
        }

        if (!parsed.featuresData) {
            console.log('[OPNet] extractMLDSA: no features data');
            return null;
        }

        const features = decodeFeaturesData(parsed.flags, parsed.featuresData);
        const mldsaFeature = features.find(f => f.type === 'mldsa');

        if (!mldsaFeature || !mldsaFeature.data) {
            console.log('[OPNet] extractMLDSA: no mldsa feature found');
            return null;
        }

        return parseMLDSAData(mldsaFeature.data);
    } catch (e) {
        console.warn('[OPNet] Failed to extract MLDSA from witness:', e);
        return null;
    }
}

/**
 * Parse MLDSA data buffer
 */
function parseMLDSAData(data: Buffer): MLDSALinkInfo | null {
    console.log('[OPNet] parseMLDSAData: data length:', data.length);

    // Minimum: level(1) + hash(32) + verifyRequest(1) + legacySig(64) = 98 bytes
    if (data.length < 98) {
        console.log('[OPNet] parseMLDSAData: data too short, need at least 98 bytes, got:', data.length);
        return null;
    }

    const reader = new BinaryReader(data);

    // Level (1 byte)
    const levelByte = reader.readU8();
    let level: 'LEVEL2' | 'LEVEL3' | 'LEVEL5';
    switch (levelByte) {
        case MLDSASecurityLevel.LEVEL2:
            level = 'LEVEL2';
            break;
        case MLDSASecurityLevel.LEVEL3:
            level = 'LEVEL3';
            break;
        case MLDSASecurityLevel.LEVEL5:
            level = 'LEVEL5';
            break;
        default:
            console.log('[OPNet] parseMLDSAData: invalid level byte:', levelByte);
            return null;
    }

    // Hashed public key (32 bytes)
    const hashedPublicKey = Buffer.from(reader.readBytes(32)).toString('hex');

    // Verify request (1 byte bool)
    const verifyRequest = reader.readBoolean();

    let fullPublicKey: string | undefined;

    if (verifyRequest) {
        const pubKeyLen = MLDSA_PUBLIC_KEY_LENGTHS[levelByte];
        const sigLen = MLDSA_SIGNATURE_LENGTHS[levelByte];

        console.log('[OPNet] parseMLDSAData: verifyRequest=true, expecting pubKey:', pubKeyLen, 'sig:', sigLen);

        if (reader.bytesLeft() >= pubKeyLen + sigLen + 64) {
            fullPublicKey = Buffer.from(reader.readBytes(pubKeyLen)).toString('hex');
            reader.readBytes(sigLen); // Skip MLDSA signature
            console.log('[OPNet] parseMLDSAData: read full public key:', fullPublicKey.substring(0, 32) + '...');
        } else {
            console.log('[OPNet] parseMLDSAData: not enough bytes for full key+sig, bytesLeft:', reader.bytesLeft());
        }
    }

    // Legacy Schnorr signature (64 bytes)
    let legacySignature = '';
    if (reader.bytesLeft() >= 64) {
        legacySignature = Buffer.from(reader.readBytes(64)).toString('hex');
        console.log('[OPNet] parseMLDSAData: read legacy signature:', legacySignature.substring(0, 32) + '...');
    } else {
        console.log('[OPNet] parseMLDSAData: not enough bytes for legacy signature, bytesLeft:', reader.bytesLeft());
    }

    console.log('[OPNet] parseMLDSAData: SUCCESS level:', level, 'hash:', hashedPublicKey.substring(0, 16) + '...');

    return {
        level,
        hashedPublicKey,
        fullPublicKey,
        legacySignature,
        isVerified: true,
        verifyRequest,
    };
}

/**
 * Get full parsed OPNet data from witness including header info
 */
export interface FullOPNetWitnessData {
    features: OPNetFeatures;
    priorityFeeSat: bigint;
    publicKeyPrefix: number;
    minerMLDSAPublicKey: string;
    solution: string;
    epochSubmission?: EpochSubmissionInfo;
    mldsaLink?: MLDSALinkInfo;
}

export function parseFullOPNetWitness(witness: string[], blockHeight?: number): FullOPNetWitnessData | null {
    if (!witness || witness.length < 4) {
        return null;
    }

    try {
        const rawScript = witness[3];
        if (!rawScript) {
            return null;
        }

        const parsed = parseOPNetScript(rawScript);
        if (!parsed) {
            return null;
        }

        const opnetFeatures: OPNetFeatures = {
            hasAccessList: (parsed.flags & Features.ACCESS_LIST) === Features.ACCESS_LIST,
            hasEpochSubmission: (parsed.flags & Features.EPOCH_SUBMISSION) === Features.EPOCH_SUBMISSION,
            hasMLDSALink: (parsed.flags & Features.MLDSA_LINK_PUBKEY) === Features.MLDSA_LINK_PUBKEY,
            featureFlags: parsed.flags,
        };

        const result: FullOPNetWitnessData = {
            features: opnetFeatures,
            priorityFeeSat: parsed.priorityFeeSat,
            publicKeyPrefix: parsed.publicKeyPrefix,
            minerMLDSAPublicKey: parsed.minerMLDSAPublicKey.toString('hex'),
            solution: parsed.solution.toString('hex'),
        };

        if (parsed.featuresData && parsed.flags !== 0) {
            const decodedFeatures = decodeFeaturesData(parsed.flags, parsed.featuresData);

            for (const feature of decodedFeatures) {
                if (feature.type === 'epoch') {
                    const epochData = feature.data;
                    // Epoch format: publicKey(32) + solution(20) + optional graffiti
                    if (epochData.length >= 52) {
                        const epochReader = new BinaryReader(epochData);
                        const mldsaPublicKey = Buffer.from(epochReader.readBytes(32));
                        const epochSolution = Buffer.from(epochReader.readBytes(20));

                        let graffiti: string | undefined;
                        let graffitiHex: string | undefined;

                        if (epochReader.bytesLeft() > 0) {
                            try {
                                const graffitiBytes = Buffer.from(epochReader.readBytesWithLength());
                                if (graffitiBytes.length > 0) {
                                    graffitiHex = graffitiBytes.toString('hex');
                                    try {
                                        graffiti = graffitiBytes.toString('utf-8');
                                    } catch {}
                                }
                            } catch {}
                        }

                        // Submissions are for epoch + 2
                        const currentEpoch = blockHeight !== undefined ? Math.floor(blockHeight / 5) : 0;
                        const submissionEpoch = currentEpoch + 2;
                        const epochNumber = submissionEpoch.toString();

                        result.epochSubmission = {
                            epochNumber,
                            minerPublicKey: mldsaPublicKey.toString('hex'),
                            solution: epochSolution.toString('hex'),
                            salt: parsed.solution.toString('hex'),
                            graffiti,
                            graffitiHex,
                            signature: '',
                        };
                    }
                } else if (feature.type === 'mldsa') {
                    result.mldsaLink = parseMLDSAData(feature.data) ?? undefined;
                }
            }
        }

        return result;
    } catch (e) {
        console.warn('[OPNet] Failed to parse full witness:', e);
        return null;
    }
}
