import { PATH } from '../common'
import { TransferTxType } from '@zondax/ledger-kadena'

export const TRANSACTIONS_TEST_CASES = [
  {
    name: 'transfer_1',
    type: TransferTxType.TRANSFER,
    path: PATH,
    recipient: '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790',
    amount: "1.23",
    network: "testnet04",
    chainId: 0,
    gasPrice: "1.0e-6",
    gasLimit: "2300",
    creationTime: 1665647810,
    ttl: "600",
    nonce: "2022-10-13 07:56:50.893257 UTC",
    blob: '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","adfas",4,5,6,7,8],"name":"mycoin.MY_TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
  },
//   {
//     name: 'transfer_create_1',
//     type: TransferTxType.TRANSFER_CREATE,
//     path: PATH,
//     recipient: '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790',
//     amount: "23.67",
//     network: "testnet04",
//     chainId: 1,
//     gasPrice: "1.0e-6",
//     gasLimit: "2300",
//     creationTime: 1665722463,
//     ttl: "600",
//     nonce: "2022-10-14 04:41:03.193557 UTC"
//   },
//   {
//     name: 'transfer_cross_chain_1',
//     type: TransferTxType.TRANSFER_CROSS_CHAIN,
//     path: PATH,
//     recipient: '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790',
//     recipient_chainId: 2,
//     amount: "23.67",
//     network: "testnet04",
//     chainId: 1,
//     gasPrice: "1.0e-6",
//     gasLimit: "2300",
//     creationTime: 1665722463,
//     ttl: "600",
//     nonce: "2022-10-14 04:41:03.193557 UTC"
//   },
//   {
//     name: 'transfer_2',
//     type: TransferTxType.TRANSFER,
//     path: PATH,
//     recipient: '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790',
//     amount: "1.23",
//     namespace: "free",
//     module: "mytoken-123",
//     network: "testnet04",
//     chainId: 0,
//     gasPrice: "1.0e-6",
//     gasLimit: "2300",
//     creationTime: 1665647810,
//     ttl: "600",
//     nonce: "2022-10-13 07:56:50.893257 UTC"
//   },
//   {
//     name: 'transfer_create_2',
//     type: TransferTxType.TRANSFER_CREATE,
//     path: PATH,
//     recipient: '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790',
//     amount: "23.67",
//     namespace: "free",
//     module: "mytoken-123",
//     network: "testnet04",
//     chainId: 1,
//     gasPrice: "1.0e-6",
//     gasLimit: "2300",
//     creationTime: 1665722463,
//     ttl: "600",
//     nonce: "2022-10-14 04:41:03.193557 UTC"
//   },
//   {
//     name: 'transfer_cross_chain_2',
//     type: TransferTxType.TRANSFER_CROSS_CHAIN,
//     path: PATH,
//     recipient: '83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790',
//     recipient_chainId: 2,
//     amount: "23.67",
//     namespace: "free",
//     module: "mytoken-123",
//     network: "testnet04",
//     chainId: 1,
//     gasPrice: "1.0e-6",
//     gasLimit: "2300",
//     creationTime: 1665722463,
//     ttl: "600",
//     nonce: "2022-10-14 04:41:03.193557 UTC"
//   }
]
