import {
  ChangeDetectionStrategy,
  Component,
  Input,
  OnChanges,
  SimpleChanges,
} from '@angular/core';
import { Transaction } from '@interfaces/electrs.interface';

interface FlowNode {
  x: number;
  y: number;
  width: number;
  height: number;
  label: string;
  value?: number;
}

interface FlowPath {
  d: string;
  strokeWidth: number;
  color: string;
}

@Component({
  selector: 'app-contract-flow-graph',
  templateUrl: './contract-flow-graph.component.html',
  styleUrls: ['./contract-flow-graph.component.scss'],
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ContractFlowGraphComponent implements OnChanges {
  @Input() tx: Transaction;
  @Input() contractType: 'deployment' | 'interaction' | 'unknown' = 'unknown';
  @Input() contractAddress: string = '';
  @Input() width = 600;
  @Input() height = 200;

  inputPaths: FlowPath[] = [];
  outputPaths: FlowPath[] = [];
  contractNode: FlowNode;

  gradientColors = {
    deployment: { start: '#28a745', end: '#1e7e34' },
    interaction: { start: '#9339f4', end: '#6225b2' },
    unknown: { start: '#007cfa', end: '#0056b3' },
  };

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['tx'] || changes['width'] || changes['height']) {
      this.calculateLayout();
    }
  }

  private calculateLayout(): void {
    if (!this.tx) {
      return;
    }

    const padding = 20;
    const nodeWidth = 120;
    const nodeHeight = 60;
    const centerX = this.width / 2;
    const centerY = this.height / 2;

    // Contract node in center
    this.contractNode = {
      x: centerX - nodeWidth / 2,
      y: centerY - nodeHeight / 2,
      width: nodeWidth,
      height: nodeHeight,
      label: this.contractType === 'deployment' ? 'Deploy' : 'Call',
    };

    // Calculate input paths
    this.inputPaths = this.calculateInputPaths(padding, centerX, centerY, nodeHeight);

    // Calculate output paths
    this.outputPaths = this.calculateOutputPaths(padding, centerX, centerY, nodeWidth, nodeHeight);
  }

  private calculateInputPaths(
    padding: number,
    centerX: number,
    centerY: number,
    nodeHeight: number
  ): FlowPath[] {
    const paths: FlowPath[] = [];
    const inputCount = Math.min(this.tx.vin.length, 5); // Limit to 5 for visualization
    const totalInputValue = this.tx.vin.reduce((sum, vin) => sum + (vin.prevout?.value || 0), 0);

    if (inputCount === 0) {
      return paths;
    }

    const startX = padding;
    const endX = centerX - 60;
    const verticalSpacing = Math.min(30, (this.height - 2 * padding) / inputCount);
    const startY = centerY - ((inputCount - 1) * verticalSpacing) / 2;

    for (let i = 0; i < inputCount; i++) {
      const vin = this.tx.vin[i];
      const value = vin.prevout?.value || 0;
      const y = startY + i * verticalSpacing;

      // Calculate stroke width based on value proportion
      const proportion = totalInputValue > 0 ? value / totalInputValue : 1 / inputCount;
      const strokeWidth = Math.max(2, Math.min(8, proportion * 20));

      // Create bezier curve path
      const controlX1 = startX + (endX - startX) * 0.4;
      const controlX2 = startX + (endX - startX) * 0.6;
      const d = `M ${startX} ${y} C ${controlX1} ${y}, ${controlX2} ${centerY}, ${endX} ${centerY}`;

      paths.push({
        d,
        strokeWidth,
        color: this.getGradientId(),
      });
    }

    return paths;
  }

  private calculateOutputPaths(
    padding: number,
    centerX: number,
    centerY: number,
    nodeWidth: number,
    nodeHeight: number
  ): FlowPath[] {
    const paths: FlowPath[] = [];
    const outputCount = Math.min(this.tx.vout.length, 5); // Limit to 5 for visualization
    const totalOutputValue = this.tx.vout.reduce((sum, vout) => sum + vout.value, 0);

    if (outputCount === 0) {
      return paths;
    }

    const startX = centerX + 60;
    const endX = this.width - padding;
    const verticalSpacing = Math.min(30, (this.height - 2 * padding) / outputCount);
    const endY = centerY - ((outputCount - 1) * verticalSpacing) / 2;

    for (let i = 0; i < outputCount; i++) {
      const vout = this.tx.vout[i];
      const y = endY + i * verticalSpacing;

      // Calculate stroke width based on value proportion
      const proportion = totalOutputValue > 0 ? vout.value / totalOutputValue : 1 / outputCount;
      const strokeWidth = Math.max(2, Math.min(8, proportion * 20));

      // Create bezier curve path
      const controlX1 = startX + (endX - startX) * 0.4;
      const controlX2 = startX + (endX - startX) * 0.6;
      const d = `M ${startX} ${centerY} C ${controlX1} ${centerY}, ${controlX2} ${y}, ${endX} ${y}`;

      paths.push({
        d,
        strokeWidth,
        color: this.getGradientId(),
      });
    }

    return paths;
  }

  getGradientId(): string {
    return `flow-gradient-${this.contractType}`;
  }

  getGradientColors(): { start: string; end: string } {
    return this.gradientColors[this.contractType] || this.gradientColors.unknown;
  }

  truncateAddress(address: string): string {
    if (!address || address.length <= 16) {
      return address || '';
    }
    return address.substring(0, 8) + '...' + address.substring(address.length - 6);
  }
}
