/**
 * OPNet Witness Data Parsing Utilities
 * Parses MLDSA/BIP360 and other feature data from raw transaction witness
 *
 * Uses @btc-vision/bitcoin script.decompile() to properly parse witness scripts
 * matching the OPNet node implementation.
 */

import { script, opcodes } from '@btc-vision/bitcoin';
import { BinaryReader } from '@btc-vision/transaction';

// Feature flags from @btc-vision/transaction Features enum
const Features = {
    ACCESS_LIST: 0b1,
    EPOCH_SUBMISSION: 0b10,
    MLDSA_LINK_PUBKEY: 0b100,
} as const;

// Feature priority order for decoding
const FeaturePriority = {
    ACCESS_LIST: 0,
    EPOCH_SUBMISSION: 1,
    MLDSA_LINK_PUBKEY: 2,
} as const;

// ML-DSA security levels
const MLDSASecurityLevel = {
    LEVEL2: 0,
    LEVEL3: 1,
    LEVEL5: 2,
} as const;

// ML-DSA public key lengths by level
const MLDSA_PUBLIC_KEY_LENGTHS: Record<number, number> = {
    [MLDSASecurityLevel.LEVEL2]: 1312,
    [MLDSASecurityLevel.LEVEL3]: 1952,
    [MLDSASecurityLevel.LEVEL5]: 2592,
};

// ML-DSA signature lengths by level
const MLDSA_SIGNATURE_LENGTHS: Record<number, number> = {
    [MLDSASecurityLevel.LEVEL2]: 2420,
    [MLDSASecurityLevel.LEVEL3]: 3293,
    [MLDSASecurityLevel.LEVEL5]: 4595,
};

// Expected header length: prefix(1) + flags(3) + priorityFee(8) = 12 bytes
const OPNET_HEADER_LENGTH = 12;

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

interface PriorityOrder {
    priority: number;
    feature: number;
}

interface DecodedFeature {
    type: 'accessList' | 'epoch' | 'mldsa';
    data: Buffer;
}

/**
 * OPNetHeader class matching the node implementation
 * Handles the 12-byte header: prefix(1) + flags(3) + priorityFee(8)
 */
class OPNetHeader {
    public static readonly EXPECTED_HEADER_LENGTH = OPNET_HEADER_LENGTH;

    private readonly _priorityFeeSat: bigint;
    private readonly _headerBytes: Uint8Array;
    private _prefix: number = 0;
    private _flags: number = 0;

    constructor(
        header: Buffer,
        public readonly minerMLDSAPublicKey: Buffer,
        public readonly solution: Buffer,
    ) {
        const reader = new BinaryReader(header);
        this._headerBytes = reader.readBytes(4);
        this._priorityFeeSat = reader.readU64();
        this.decodeHeader();
    }

    public get priorityFeeSat(): bigint {
        return this._priorityFeeSat;
    }

    public get publicKeyPrefix(): number {
        return this._prefix;
    }

    public get flags(): number {
        return this._flags;
    }

    public decodeFlags(): PriorityOrder[] {
        const features: PriorityOrder[] = [];

        const includesAccessList = (this._flags & Features.ACCESS_LIST) === Features.ACCESS_LIST;
        const includesEpochSubmission = (this._flags & Features.EPOCH_SUBMISSION) === Features.EPOCH_SUBMISSION;
        const includesMLDSALinkingRequest = (this._flags & Features.MLDSA_LINK_PUBKEY) === Features.MLDSA_LINK_PUBKEY;

        if (includesAccessList) {
            features.push({
                priority: FeaturePriority.ACCESS_LIST,
                feature: Features.ACCESS_LIST,
            });
        }

        if (includesEpochSubmission) {
            features.push({
                priority: FeaturePriority.EPOCH_SUBMISSION,
                feature: Features.EPOCH_SUBMISSION,
            });
        }

        if (includesMLDSALinkingRequest) {
            features.push({
                priority: FeaturePriority.MLDSA_LINK_PUBKEY,
                feature: Features.MLDSA_LINK_PUBKEY,
            });
        }

        return features;
    }

    private decodeHeader(): void {
        this._prefix = this._headerBytes[0];

        if (this._prefix !== 0x02 && this._prefix !== 0x03) {
            throw new Error('Invalid public key prefix');
        }

        const flagBuffer = Buffer.from(this._headerBytes.slice(1));
        this._flags = flagBuffer.readUIntBE(0, 3);
    }
}

/**
 * Parsed OPNet script structure
 */
interface ParsedOPNetScript {
    header: OPNetHeader;
    featuresData: Buffer | null;
}

/**
 * Decompile and parse the OPNet script from witness[3]
 * Uses script.decompile() to properly extract pushed data buffers
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

    // Create a mutable copy to shift elements from
    const scriptData: (number | Buffer)[] = [...decodedScript];

    // 1. Read header (12 bytes)
    const header = scriptData.shift();
    if (!Buffer.isBuffer(header) || header.length !== OPNetHeader.EXPECTED_HEADER_LENGTH) {
        console.log('[OPNet] parseScript: invalid header, got length:', Buffer.isBuffer(header) ? header.length : 'not a buffer');
        return null;
    }

    // 2. Expect OP_TOALTSTACK
    if (scriptData.shift() !== opcodes.OP_TOALTSTACK) {
        console.log('[OPNet] parseScript: expected OP_TOALTSTACK after header');
        return null;
    }

    // 3. Read minerMLDSAPublicKey (32 bytes)
    const minerMLDSAPublicKey = scriptData.shift();
    if (!Buffer.isBuffer(minerMLDSAPublicKey) || minerMLDSAPublicKey.length !== 32) {
        console.log('[OPNet] parseScript: invalid minerMLDSAPublicKey');
        return null;
    }

    // 4. Expect OP_TOALTSTACK
    if (scriptData.shift() !== opcodes.OP_TOALTSTACK) {
        console.log('[OPNet] parseScript: expected OP_TOALTSTACK after minerMLDSAPublicKey');
        return null;
    }

    // 5. Read preimage/solution (variable length)
    const preimage = scriptData.shift();
    if (!Buffer.isBuffer(preimage)) {
        console.log('[OPNet] parseScript: invalid preimage');
        return null;
    }

    // 6. Expect OP_TOALTSTACK
    if (scriptData.shift() !== opcodes.OP_TOALTSTACK) {
        console.log('[OPNet] parseScript: expected OP_TOALTSTACK after preimage');
        return null;
    }

    // Create header object
    const opnetHeader = new OPNetHeader(header, minerMLDSAPublicKey, preimage);

    // 7. Read features data if any flags are set
    let featuresData: Buffer | null = null;
    if (opnetHeader.flags !== 0) {
        featuresData = getDataUntilBufferEnd(scriptData);
    }

    return {
        header: opnetHeader,
        featuresData,
    };
}

/**
 * Read all consecutive buffer data from script array
 * Matching SharedInteractionParameters.getDataUntilBufferEnd
 */
function getDataUntilBufferEnd(scriptData: (number | Buffer)[]): Buffer | null {
    let data: Buffer | null = null;

    while (scriptData.length > 0) {
        const currentItem = scriptData[0];

        if (!Buffer.isBuffer(currentItem)) {
            break;
        }

        scriptData.shift();
        data = data ? Buffer.concat([data, currentItem]) : currentItem;
    }

    return data;
}

/**
 * Decode features data based on priority order
 * Each feature is stored as: U32 length (big-endian via readBytesWithLength) + data
 */
function decodeFeaturesData(flags: number, data: Buffer): DecodedFeature[] {
    const features: DecodedFeature[] = [];
    const reader = new BinaryReader(data);

    // Get features in priority order
    const featureOrder: Array<{ flag: number; type: DecodedFeature['type'] }> = [
        { flag: Features.ACCESS_LIST, type: 'accessList' },
        { flag: Features.EPOCH_SUBMISSION, type: 'epoch' },
        { flag: Features.MLDSA_LINK_PUBKEY, type: 'mldsa' },
    ];

    for (const { flag, type } of featureOrder) {
        if ((flags & flag) === flag) {
            try {
                // readBytesWithLength reads U32 big-endian length then data
                const featureData = Buffer.from(reader.readBytesWithLength());
                features.push({ type, data: featureData });
            } catch (e) {
                console.log(`[OPNet] decodeFeaturesData: failed to read ${type}:`, e);
                break;
            }
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
        console.log('[OPNet] parseFeatures: witness too short, length:', witness?.length);
        return null;
    }

    try {
        const rawScript = witness[3];
        if (!rawScript) {
            console.log('[OPNet] parseFeatures: witness[3] is empty');
            return null;
        }

        const parsed = parseOPNetScript(rawScript);
        if (!parsed) {
            return null;
        }

        const flags = parsed.header.flags;

        return {
            hasAccessList: (flags & Features.ACCESS_LIST) === Features.ACCESS_LIST,
            hasEpochSubmission: (flags & Features.EPOCH_SUBMISSION) === Features.EPOCH_SUBMISSION,
            hasMLDSALink: (flags & Features.MLDSA_LINK_PUBKEY) === Features.MLDSA_LINK_PUBKEY,
            featureFlags: flags,
        };
    } catch (e) {
        console.warn('[OPNet] Failed to parse features from witness:', e);
        return null;
    }
}

/**
 * Extract Epoch Submission info from witness data
 * Format: mldsaPublicKey(32) + salt(32) + graffiti(optional with length)
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

        const flags = parsed.header.flags;
        if ((flags & Features.EPOCH_SUBMISSION) !== Features.EPOCH_SUBMISSION) {
            return null;
        }

        const features = decodeFeaturesData(flags, parsed.featuresData);
        const epochFeature = features.find(f => f.type === 'epoch');

        if (!epochFeature || !epochFeature.data) {
            return null;
        }

        const data = epochFeature.data;
        if (data.length < 64) {
            console.log('[OPNet] extractEpochSubmission: data too short');
            return null;
        }

        const reader = new BinaryReader(data);

        const mldsaPublicKey = Buffer.from(reader.readBytes(32));
        const salt = Buffer.from(reader.readBytes(32));

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
        const epochNumber = blockHeight !== undefined ? Math.floor(blockHeight / 5).toString() : '0';

        return {
            epochNumber,
            minerPublicKey: mldsaPublicKey.toString('hex'),
            solution: parsed.header.solution.toString('hex'),
            salt: salt.toString('hex'),
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
 * Format: level(u8) + hashedPubKey(32) + verifyRequest(bool) + [optional pubkey+sig] + legacySig(64)
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

        const flags = parsed.header.flags;
        if ((flags & Features.MLDSA_LINK_PUBKEY) !== Features.MLDSA_LINK_PUBKEY) {
            console.log('[OPNet] extractMLDSA: MLDSA flag not set, flags:', flags);
            return null;
        }

        if (!parsed.featuresData) {
            console.log('[OPNet] extractMLDSA: no features data');
            return null;
        }

        const features = decodeFeaturesData(flags, parsed.featuresData);
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
 * Format: level(u8) + hashedPubKey(32) + verifyRequest(bool) + [optional pubkey+sig] + legacySig(64)
 */
function parseMLDSAData(data: Buffer): MLDSALinkInfo | null {
    if (data.length < 34) {
        console.log('[OPNet] parseMLDSAData: data too short, need at least 34 bytes, got:', data.length);
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

        if (reader.bytesLeft() >= pubKeyLen + sigLen + 64) {
            fullPublicKey = Buffer.from(reader.readBytes(pubKeyLen)).toString('hex');
            // Skip MLDSA signature
            reader.readBytes(sigLen);
        } else {
            console.log('[OPNet] parseMLDSAData: not enough data for pubkey+sig, need:', pubKeyLen + sigLen, 'have:', reader.bytesLeft());
        }
    }

    // Legacy Schnorr signature (64 bytes)
    let legacySignature = '';
    if (reader.bytesLeft() >= 64) {
        legacySignature = Buffer.from(reader.readBytes(64)).toString('hex');
    } else {
        console.log('[OPNet] parseMLDSAData: no legacy signature, remaining:', reader.bytesLeft());
    }

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

        const flags = parsed.header.flags;

        const features: OPNetFeatures = {
            hasAccessList: (flags & Features.ACCESS_LIST) === Features.ACCESS_LIST,
            hasEpochSubmission: (flags & Features.EPOCH_SUBMISSION) === Features.EPOCH_SUBMISSION,
            hasMLDSALink: (flags & Features.MLDSA_LINK_PUBKEY) === Features.MLDSA_LINK_PUBKEY,
            featureFlags: flags,
        };

        const result: FullOPNetWitnessData = {
            features,
            priorityFeeSat: parsed.header.priorityFeeSat,
            publicKeyPrefix: parsed.header.publicKeyPrefix,
            minerMLDSAPublicKey: parsed.header.minerMLDSAPublicKey.toString('hex'),
            solution: parsed.header.solution.toString('hex'),
        };

        if (parsed.featuresData && flags !== 0) {
            const decodedFeatures = decodeFeaturesData(flags, parsed.featuresData);

            for (const feature of decodedFeatures) {
                if (feature.type === 'epoch') {
                    const reader = new BinaryReader(feature.data);
                    if (feature.data.length >= 64) {
                        const mldsaPublicKey = Buffer.from(reader.readBytes(32));
                        const salt = Buffer.from(reader.readBytes(32));

                        let graffiti: string | undefined;
                        let graffitiHex: string | undefined;

                        if (reader.bytesLeft() > 0) {
                            try {
                                const graffitiBytes = Buffer.from(reader.readBytesWithLength());
                                if (graffitiBytes.length > 0) {
                                    graffitiHex = graffitiBytes.toString('hex');
                                    try {
                                        graffiti = graffitiBytes.toString('utf-8');
                                    } catch {
                                        // ignore
                                    }
                                }
                            } catch {
                                // ignore
                            }
                        }

                        const epochNumber = blockHeight !== undefined ? Math.floor(blockHeight / 5).toString() : '0';

                        result.epochSubmission = {
                            epochNumber,
                            minerPublicKey: mldsaPublicKey.toString('hex'),
                            solution: parsed.header.solution.toString('hex'),
                            salt: salt.toString('hex'),
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