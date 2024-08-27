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

import Zemu, { ButtonKind, zondaxMainmenuNavigation, isTouchDevice } from '@zondax/zemu'
import { KadenaApp } from '@zondax/ledger-kadena'
import { PATH, defaultOptions, models, simpleTxNormal } from './common'
import { blake2bFinal, blake2bInit, blake2bUpdate } from 'blakejs'

import { HASH_TEST_CASES } from './testscases/hash'
import { TRANSACTIONS_TEST_CASES } from './testscases/transactions'

// @ts-expect-error
import ed25519 from 'ed25519-supercop'

jest.setTimeout(60000)

describe.each(HASH_TEST_CASES)('Hash transactions', function (data) {
  test.concurrent.each(models)('sign', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())

      const responseAddr = await app.getAddressAndPubKey(data.path)
      const pubKey = responseAddr.pubkey

      // do not wait here... we need to navigate
      const signatureRequest = app.signHash(data.path, data.hash)

      // // Wait until we are not in the main menu
      // await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      // await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_${data.name}`)

      // const signatureResponse = await signatureRequest
      // console.log(signatureResponse)

      // const rawHash =
      //   typeof data.hash == 'string'
      //     ? data.hash.length == 64
      //       ? Buffer.from(data.hash, 'hex')
      //       : Buffer.from(data.hash, 'base64')
      //     : Buffer.from(data.hash)
      // // Now verify the signature
      // const valid = ed25519.verify(signatureResponse.signature, rawHash, pubKey)
      // expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe.each(TRANSACTIONS_TEST_CASES)('Tx transactions', function (data) {
  test.only.each(models)('sign', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())

      const responseAddr = await app.getAddressAndPubKey(data.path)
      const pubKey = responseAddr.pubkey

      // do not wait here... we need to navigate
      const signatureRequest = app.signTransferTx(data.path, data)

      // // Wait until we are not in the main menu
      // await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      // await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_${data.name}`)

      // const signatureResponse = await signatureRequest
      // console.log(signatureResponse)

      // const rawHash =
      //   typeof data.hash == 'string'
      //     ? data.hash.length == 64
      //       ? Buffer.from(data.hash, 'hex')
      //       : Buffer.from(data.hash, 'base64')
      //     : Buffer.from(data.hash)
      // // Now verify the signature
      // const valid = ed25519.verify(signatureResponse.signature, rawHash, pubKey)
      // expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
