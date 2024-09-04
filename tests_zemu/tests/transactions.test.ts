/** ******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu from '@zondax/zemu'
import { KadenaApp, TransferTxType, TransferCrossChainTxParams } from '@zondax/ledger-kadena'
import { PATH, defaultOptions, models } from './common'
import { blake2bFinal, blake2bInit, blake2bUpdate } from 'blakejs'

import { JSON_TEST_CASES } from './testscases/json'
import { HASH_TEST_CASES } from './testscases/hash'
import { TRANSACTIONS_TEST_CASES } from './testscases/transactions'

// @ts-expect-error
import ed25519 from 'ed25519-supercop'

jest.setTimeout(60000)

describe.each(JSON_TEST_CASES)('Tx json', function (data) {
  test.concurrent.each(models)('sign json', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())

      const txBlob = Buffer.from(data.json, 'utf-8')
      const responseAddr = await app.getAddressAndPubKey(data.path, false)
      const pubKey = responseAddr.pubkey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(data.path, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_${data.name}`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      const context = blake2bInit(32)
      blake2bUpdate(context, txBlob)
      const hash = Buffer.from(blake2bFinal(context))

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, hash, pubKey)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe.each(HASH_TEST_CASES)('Hash transactions', function (data) {
  test.concurrent.each(models)('sign hash', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())

      const responseAddr = await app.getAddressAndPubKey(data.path)
      const pubKey = responseAddr.pubkey

      await sim.toggleExpertMode()
      // do not wait here... we need to navigate
      const signatureRequest = app.signHash(data.path, data.hash)

      // // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_${data.name}`)

      const signatureResponse = await signatureRequest

      const rawHash =
        typeof data.hash == 'string'
          ? data.hash.length == 64
            ? Buffer.from(data.hash, 'hex')
            : Buffer.from(data.hash, 'base64')
          : Buffer.from(data.hash)

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, rawHash, pubKey)

      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe.each(TRANSACTIONS_TEST_CASES)('Tx transfer', function (data) {
  test.concurrent.each(models)('sign transfer tx', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())

      const responseAddr = await app.getAddressAndPubKey(data.txParams.path)
      const pubKey = responseAddr.pubkey

      var signatureRequest = null
      // do not wait here... we need to navigate
      if (data.type === TransferTxType.TRANSFER) {
        signatureRequest = app.signTransferTx(data.txParams.path, data.txParams)
      } else if (data.type === TransferTxType.TRANSFER_CREATE) {
        signatureRequest = app.signTransferCreateTx(data.txParams.path, data.txParams)
      } else if (data.type === TransferTxType.TRANSFER_CROSS_CHAIN) {
        const transferCrossChainParams = data.txParams as TransferCrossChainTxParams
        if (data.txParams.recipient_chainId !== undefined) {
          transferCrossChainParams.recipient_chainId = data.txParams.recipient_chainId
        } else {
          throw new Error('recipient_chainId is undefined')
        }
        signatureRequest = app.signTransferCrossChainTx(data.txParams.path, transferCrossChainParams)
      }

      if (signatureRequest == null) {
        throw new Error('Signature request is null')
      }

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_${data.name}`)

      const signatureResponse = await signatureRequest

      const decodedHash = decodeHash(signatureResponse.hash)

      console.log('Pubkey: ', pubKey.toString('hex'))
      console.log('Signature: ', signatureResponse.signature.toString('hex'))
      console.log('Decoded Hash: ', decodedHash.toString('hex'))

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, decodedHash, pubKey)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

function decodeHash(encodedHash: string): Buffer {
  let base64Hash = encodedHash.replace(/-/g, '+').replace(/_/g, '/')

  while (base64Hash.length % 4) {
    base64Hash += '='
  }

  return Buffer.from(base64Hash, 'base64')
}
