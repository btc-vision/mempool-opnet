import {
  ChangeDetectionStrategy,
  Component,
  Input,
} from '@angular/core';

export interface ContractEvent {
  contractAddress: string;
  type: string;
  data?: string;
  decodedProperties?: Record<string, unknown>;
}

@Component({
  selector: 'app-contract-events',
  templateUrl: './contract-events.component.html',
  styleUrls: ['./contract-events.component.scss'],
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ContractEventsComponent {
  @Input() events: ContractEvent[] = [];

  isCollapsed = false;
  expandedEvents: { [index: number]: boolean } = {};

  toggleEvent(index: number): void {
    this.expandedEvents[index] = !this.expandedEvents[index];
  }

  isEventExpanded(index: number): boolean {
    return this.expandedEvents[index] || false;
  }

  truncateAddress(address: string, chars: number = 8): string {
    if (!address || address.length <= chars * 2) {
      return address || '';
    }
    return address.substring(0, chars) + '...' + address.substring(address.length - chars);
  }

  formatValue(value: unknown): string {
    if (value === null || value === undefined) {
      return 'null';
    }
    if (typeof value === 'object') {
      return JSON.stringify(value, null, 2);
    }
    return String(value);
  }

  getPropertyEntries(properties: Record<string, unknown>): [string, unknown][] {
    if (!properties) {
      return [];
    }
    return Object.entries(properties);
  }

  copyToClipboard(text: string): void {
    navigator.clipboard.writeText(text);
  }
}
