import {
  ChangeDetectionStrategy,
  Component,
  Input,
  OnChanges,
} from '@angular/core';
import { calcSegwitFeeGains, isFeatureActive } from '@app/bitcoin.utils';
import { Transaction } from '@interfaces/electrs.interface';
import { StateService } from '@app/services/state.service';
import { TransactionFlags } from '@app/shared/filters.utils';

@Component({
  selector: 'app-tx-features',
  templateUrl: './tx-features.component.html',
  styleUrls: ['./tx-features.component.scss'],
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TxFeaturesComponent implements OnChanges {
  @Input() tx: Transaction;

  segwitGains = {
    realizedSegwitGains: 0,
    potentialSegwitGains: 0,
    potentialP2shSegwitGains: 0,
    potentialTaprootGains: 0,
    realizedTaprootGains: 0,
  };
  isRbfTransaction: boolean;
  isTaproot: boolean;
  isSmartContract: boolean;
  isBIP360Ready: boolean;

  segwitEnabled: boolean;
  rbfEnabled: boolean;
  taprootEnabled: boolean;
  smartContractsEnabled: boolean;
  bip360Enabled: boolean;

  constructor(private stateService: StateService) {}

  ngOnChanges(): void {
    if (!this.tx) {
      return;
    }

    this.segwitEnabled =
      !this.tx.status.confirmed ||
      isFeatureActive(
        this.stateService.network,
        this.tx.status.block_height,
        'segwit'
      );

    this.taprootEnabled =
      !this.tx.status.confirmed ||
      isFeatureActive(
        this.stateService.network,
        this.tx.status.block_height,
        'taproot'
      );

    this.rbfEnabled =
      !this.tx.status.confirmed ||
      isFeatureActive(
        this.stateService.network,
        this.tx.status.block_height,
        'rbf'
      );

    // OPNet smart contracts are enabled
    this.smartContractsEnabled =
      !this.tx.status.confirmed ||
      isFeatureActive(
        this.stateService.network,
        this.tx.status.block_height,
        'smart_contract'
      );

    // BIP360 is enabled (pre-quantum phase - OPNet supports MLDSA linking)
    this.bip360Enabled = true;

    this.segwitGains = calcSegwitFeeGains(this.tx);
    this.isRbfTransaction = this.tx.vin.some((v) => v.sequence < 0xfffffffe);
    this.isTaproot = this.tx.vin.some(
      (v) => v.prevout && v.prevout.scriptpubkey_type === 'v1_p2tr'
    );

    const hasP2opInput = this.tx.vin.some(
      (v) => v.prevout && v.prevout.scriptpubkey_type === 'v16_p2op'
    );
    const hasP2opOutput = this.tx.vout.some((v) => v.scriptpubkey_type === 'v16_p2op');
    const hasInteractionFlag = this.tx.flags
      ? (this.tx.flags & TransactionFlags.interaction) !== 0n
      : false;

    this.isSmartContract = hasP2opInput || hasP2opOutput || hasInteractionFlag;

    // Detect BIP360 (post-quantum / MLDSA linking)
    this.isBIP360Ready = this.tx.flags
      ? (this.tx.flags & TransactionFlags.bip360) !== 0n
      : false;
  }
}
