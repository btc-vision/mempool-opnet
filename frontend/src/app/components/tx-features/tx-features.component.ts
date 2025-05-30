import {
  ChangeDetectionStrategy,
  Component,
  Input,
  OnChanges,
} from '@angular/core';
import { calcSegwitFeeGains, isFeatureActive } from '@app/bitcoin.utils';
import { Transaction } from '@interfaces/electrs.interface';
import { StateService } from '@app/services/state.service';

@Component({
  selector: 'app-tx-features',
  templateUrl: './tx-features.component.html',
  styleUrls: ['./tx-features.component.scss'],
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

  segwitEnabled: boolean;
  rbfEnabled: boolean;
  smartContractsEnabled: boolean;
  taprootEnabled: boolean;

  constructor(private stateService: StateService) {}

  ngOnChanges() {
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

    this.smartContractsEnabled =
      !this.tx.status.confirmed ||
      isFeatureActive(
        this.stateService.network,
        this.tx.status.block_height,
        'smart_contract'
      );

    this.segwitGains = calcSegwitFeeGains(this.tx);
    this.isRbfTransaction = this.tx.vin.some((v) => v.sequence < 0xfffffffe);
    this.isTaproot = this.tx.vin.some(
      (v) => v.prevout && v.prevout.scriptpubkey_type === 'v1_p2tr'
    );
    
    this.isSmartContract =
      this.tx.vin.some(
        (v) => v.prevout && v.prevout.scriptpubkey_type === 'v16_p2op'
      ) || this.tx.vout.some((v) => v.scriptpubkey_type === 'v16_p2op');
  }
}
