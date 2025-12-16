import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Routes, RouterModule } from '@angular/router';
import { TransactionComponent } from '@components/transaction/transaction.component';
import { TransactionDetailsComponent } from '@components/transaction/transaction-details/transaction-details.component';
import { SharedModule } from '@app/shared/shared.module';
import { TxBowtieModule } from '@components/tx-bowtie-graph/tx-bowtie.module';
import { TransactionExtrasModule } from '@components/transaction/transaction-extras.module';
import { GraphsModule } from '@app/graphs/graphs.module';
import { AccelerateCheckout } from '@components/accelerate-checkout/accelerate-checkout.component';
import { AccelerateFeeGraphComponent } from '@components/accelerate-checkout/accelerate-fee-graph.component';
import { TransactionRawComponent } from '@components/transaction/transaction-raw.component';
import { CpfpInfoComponent } from '@components/transaction/cpfp-info.component';
// OPNet Smart Contract Components
import { ContractEventsComponent } from '@components/contract-events/contract-events.component';

const routes: Routes = [
  {
    path: '',
    redirectTo: '/',
    pathMatch: 'full',
  },
  {
    path: 'preview',
    component: TransactionRawComponent,
  },
  {
    path: ':id',
    component: TransactionComponent,
    data: {
      ogImage: true
    }
  }
];

@NgModule({
  imports: [
    RouterModule.forChild(routes)
  ],
  exports: [
    RouterModule
  ]
})
export class TransactionRoutingModule { }

@NgModule({
  imports: [
    CommonModule,
    TransactionRoutingModule,
    SharedModule,
    GraphsModule,
    TxBowtieModule,
    TransactionExtrasModule,
  ],
  declarations: [
    TransactionComponent,
    TransactionDetailsComponent,
    AccelerateCheckout,
    AccelerateFeeGraphComponent,
    TransactionRawComponent,
    CpfpInfoComponent,
    // OPNet Smart Contract Components
    ContractEventsComponent,
  ],
  exports: [
    TransactionComponent,
    TransactionDetailsComponent,
    AccelerateCheckout,
    AccelerateFeeGraphComponent,
    CpfpInfoComponent,
    // OPNet Smart Contract Components
    ContractEventsComponent,
  ]
})
export class TransactionModule { }






