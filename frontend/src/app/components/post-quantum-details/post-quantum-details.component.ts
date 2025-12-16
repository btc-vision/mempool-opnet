import {
  ChangeDetectionStrategy,
  Component,
  Input,
} from '@angular/core';

export interface PostQuantumInfo {
  mldsaPublicKey: string;
  tweakedKey: string;
  legacySignatureType: 'schnorr' | 'ecdsa';
  securityLevel: 'LEVEL2' | 'LEVEL3' | 'LEVEL5';
  algorithm: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
}

@Component({
  selector: 'app-post-quantum-details',
  templateUrl: './post-quantum-details.component.html',
  styleUrls: ['./post-quantum-details.component.scss'],
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PostQuantumDetailsComponent {
  @Input() pqInfo: PostQuantumInfo;

  getSecurityBadgeClass(): string {
    switch (this.pqInfo?.securityLevel) {
      case 'LEVEL2':
        return 'badge-level2';
      case 'LEVEL3':
        return 'badge-level3';
      case 'LEVEL5':
        return 'badge-level5';
      default:
        return 'badge-secondary';
    }
  }

  getSecurityDescription(): string {
    switch (this.pqInfo?.securityLevel) {
      case 'LEVEL2':
        return 'AES-128 equivalent security';
      case 'LEVEL3':
        return 'AES-192 equivalent security';
      case 'LEVEL5':
        return 'AES-256 equivalent security';
      default:
        return '';
    }
  }

  copyToClipboard(text: string): void {
    navigator.clipboard.writeText(text);
  }

  truncateKey(key: string, length: number = 32): string {
    if (!key || key.length <= length) {
      return key;
    }
    return key.substring(0, length) + '...';
  }
}
