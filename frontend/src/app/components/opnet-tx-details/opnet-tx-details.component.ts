import {
  ChangeDetectionStrategy,
  Component,
  Input,
} from '@angular/core';

export interface OPNetFeatures {
  hasAccessList: boolean;
  hasEpochSubmission: boolean;
  hasMLDSALink: boolean;
  featureFlags: number;
}

export interface MLDSALinkInfo {
  level: 'LEVEL2' | 'LEVEL3' | 'LEVEL5';
  hashedPublicKey: string;
  fullPublicKey?: string;
  legacySignature: string;
  isVerified: boolean;
  tweakedKey?: string;
  originalKey?: string;
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

export interface OPNetTransactionExtension {
  opnetType: 'Generic' | 'Deployment' | 'Interaction';
  features?: OPNetFeatures;
  mldsaLink?: MLDSALinkInfo;
  epochSubmission?: EpochSubmissionInfo;
  interaction?: {
    contractAddress: string;
    from: string;
    calldataLength?: number;
  };
  deployment?: {
    contractAddress: string;
    bytecodeLength: number;
  };
  gasInfo?: {
    gasUsed: string | number;
    specialGasUsed: string | number;
    estimatedGas?: string | number;
    refundedGas?: string | number;
  };
  events?: any[];
  pqInfo?: any;
}

@Component({
  selector: 'app-opnet-tx-details',
  templateUrl: './opnet-tx-details.component.html',
  styleUrls: ['./opnet-tx-details.component.scss'],
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OPNetTxDetailsComponent {
  @Input() opnet: OPNetTransactionExtension | null = null;

  showFullKey = false;

  get mldsaAlgorithm(): string {
    if (!this.opnet?.mldsaLink?.level) return '';
    switch (this.opnet.mldsaLink.level) {
      case 'LEVEL2': return 'ML-DSA-44';
      case 'LEVEL3': return 'ML-DSA-65';
      case 'LEVEL5': return 'ML-DSA-87';
      default: return '';
    }
  }

  get publicKeySize(): number {
    if (!this.opnet?.mldsaLink?.fullPublicKey) return 0;
    return this.opnet.mldsaLink.fullPublicKey.length / 2; // hex to bytes
  }

  truncateKey(key: string, chars: number = 16): string {
    if (!key || key.length <= chars * 2) {
      return key || '';
    }
    return key.substring(0, chars) + '...' + key.substring(key.length - chars);
  }

  copyToClipboard(text: string): void {
    navigator.clipboard.writeText(text);
  }

  toggleFullKey(): void {
    this.showFullKey = !this.showFullKey;
  }
}
