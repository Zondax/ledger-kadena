import { PATH } from '../common'
import { TransferTxType } from '@zondax/ledger-kadena'

export const TRANSACTIONS_TEST_CASES = [
  {
    name: 'transfer_1',
    type: TransferTxType.TRANSFER,
    txParams: {
      path: PATH,
      recipient: '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790',
      amount: '1.23',
      network: 'testnet04',
      chainId: 0,
      gasPrice: '1.0e-6',
      gasLimit: '2300',
      creationTime: 1665647810,
      ttl: '600',
      nonce: '2022-10-13 07:56:50.893257 UTC',
    },
  },
  {
    name: 'transfer_create_1',
    type: TransferTxType.TRANSFER_CREATE,
    txParams: {
      path: PATH,
      recipient: '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790',
      amount: '23.67',
      network: 'testnet04',
      chainId: 1,
      gasPrice: '1.0e-6',
      gasLimit: '2300',
      creationTime: 1665722463,
      ttl: '600',
      nonce: '2022-10-14 04:41:03.193557 UTC',
    },
  },
  {
    name: 'transfer_cross_chain_1',
    type: TransferTxType.TRANSFER_CROSS_CHAIN,
    txParams: {
      path: PATH,
      recipient: '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790',
      amount: '23.67',
      network: 'testnet04',
      chainId: 1,
      gasPrice: '1.0e-6',
      gasLimit: '2300',
      creationTime: 1665722463,
      ttl: '600',
      nonce: '2022-10-14 04:41:03.193557 UTC',
      recipient_chainId: 2,
    },
  },
]
