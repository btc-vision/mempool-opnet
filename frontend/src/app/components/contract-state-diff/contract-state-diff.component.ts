import {
  ChangeDetectionStrategy,
  Component,
  Input,
  OnChanges,
  SimpleChanges,
} from '@angular/core';

export interface StorageAccess {
  storageKey: string;
  value: string;
  accessType: 'read' | 'write';
}

export interface ContractStateDiff {
  contractAddress: string;
  storageAccesses: StorageAccess[];
}

export interface AccessList {
  [contractAddress: string]: {
    [storageKey: string]: string;
  };
}

@Component({
  selector: 'app-contract-state-diff',
  templateUrl: './contract-state-diff.component.html',
  styleUrls: ['./contract-state-diff.component.scss'],
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ContractStateDiffComponent implements OnChanges {
  @Input() accessList: AccessList;

  stateDiffs: ContractStateDiff[] = [];
  isCollapsed = true;

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['accessList'] && this.accessList) {
      this.parseAccessList();
    }
  }

  private parseAccessList(): void {
    this.stateDiffs = [];

    for (const [contractAddress, storage] of Object.entries(this.accessList)) {
      const storageAccesses: StorageAccess[] = [];

      for (const [storageKey, value] of Object.entries(storage)) {
        storageAccesses.push({
          storageKey,
          value,
          accessType: 'read', // Default to read; actual type would come from API
        });
      }

      if (storageAccesses.length > 0) {
        this.stateDiffs.push({
          contractAddress,
          storageAccesses,
        });
      }
    }
  }

  getTotalAccessCount(): number {
    return this.stateDiffs.reduce(
      (sum, diff) => sum + diff.storageAccesses.length,
      0
    );
  }

  truncateKey(key: string, length: number = 16): string {
    if (!key || key.length <= length) {
      return key || '';
    }
    return key.substring(0, length) + '...';
  }

  truncateAddress(address: string, chars: number = 12): string {
    if (!address || address.length <= chars * 2) {
      return address || '';
    }
    return address.substring(0, chars) + '...' + address.substring(address.length - 6);
  }

  getAccessTypeBadgeClass(accessType: string): string {
    switch (accessType) {
      case 'read':
        return 'badge-read';
      case 'write':
        return 'badge-write';
      default:
        return 'badge-secondary';
    }
  }

  copyToClipboard(text: string): void {
    navigator.clipboard.writeText(text);
  }
}
