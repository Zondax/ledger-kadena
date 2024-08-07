import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import { KadenaApp } from '@zondax/ledger-kadena'
import { ed25519 } from '@noble/curves/ed25519'
import pkg from 'blakejs'
const { blake2bFinal, blake2bInit, blake2bUpdate } = pkg

async function main() {
  const transport = await TransportNodeHid.default.open()

  const app = new KadenaApp(transport)

  const PATH = "m/44'/626'/0'/0/0"
  //const PATH_TESTNET = "m/44'/1'/0'/0'/0'"
  const get_resp = await app.getAddressAndPubKey(PATH)
  const pubKey = get_resp.pubkey
  console.log(get_resp)
  console.log(pubKey.toString('hex'))

  let resp = await app.deviceInfo()
  console.log('Device Info', resp)
  resp = await app.getVersion()
  console.log('Version', resp)

  const blob =
    '{"networkId":"mainnet01","payload":{"exec":{"data":{"ks":{"pred":"keys-all","keys":["368820f80c324bbc7c2b0610688a7da43e39f91d118732671cd9c7500ff43cca"]}},"code":"(coin.transfer-create \\"alice\\" \\"bob\\" (read-keyset \\"ks\\") 100.1)\\n(coin.transfer \\"bob\\" \\"alice\\" 0.1)"}},"signers":[{"pubKey":"6be2f485a7af75fedb4b7f153a903f7e6000ca4aa501179c91a2450b777bd2a7","clist":[{"args":["alice","bob",100.1],"name":"coin.TRANSFER"},{"args":[],"name":"coin.GAS"}]},{"pubKey":"368820f80c324bbc7c2b0610688a7da43e39f91d118732671cd9c7500ff43cca","clist":[{"args":["bob","alice",0.1],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1580316382,"ttl":7200,"gasLimit":1200,"chainId":"0","gasPrice":1.0e-5,"sender":"alice"},"nonce":"2020-01-29 16:46:22.916695 UTC"}'
  const messageToSign = Buffer.from(blob)
  console.log(messageToSign.toString())
  const signatureRequest = app.sign(PATH, messageToSign)

  const signatureResponse = await signatureRequest
  console.log(signatureResponse.signature.toString('hex'))

  const context = blake2bInit(32)
  blake2bUpdate(context, messageToSign)
  const hash = Buffer.from(blake2bFinal(context))

  // Now verify the signature
  const valid = ed25519.verify(signatureResponse.signature, hash, pubKey)
  if (valid) {
    console.log('Valid signature')
  } else {
    console.log('Invalid signature')
  }
}

;(async () => {
  await main()
})()
