import {
  ChangeDetectionStrategy,
  Component,
  Input,
  OnChanges,
  SimpleChanges,
} from '@angular/core';

export interface GasInfo {
  estimatedGas: number;
  gasUsed: number;
  specialGasUsed: number;
  refundedGas: number;
}

@Component({
  selector: 'app-gas-breakdown',
  templateUrl: './gas-breakdown.component.html',
  styleUrls: ['./gas-breakdown.component.scss'],
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GasBreakdownComponent implements OnChanges {
  @Input() gasInfo: GasInfo;

  usedPercentage: number = 0;
  refundedPercentage: number = 0;
  efficiency: number = 0;

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['gasInfo'] && this.gasInfo) {
      this.calculatePercentages();
    }
  }

  private calculatePercentages(): void {
    const total = this.gasInfo.estimatedGas || this.gasInfo.gasUsed;

    if (total > 0) {
      this.usedPercentage = (this.gasInfo.gasUsed / total) * 100;
      this.refundedPercentage = (this.gasInfo.refundedGas / total) * 100;
      this.efficiency = 100 - this.usedPercentage;
    }
  }

  formatNumber(value: number): string {
    if (value >= 1000000) {
      return (value / 1000000).toFixed(2) + 'M';
    } else if (value >= 1000) {
      return (value / 1000).toFixed(2) + 'K';
    }
    return value.toLocaleString();
  }
}
