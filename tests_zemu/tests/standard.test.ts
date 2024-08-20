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
import { PATH, defaultOptions, models, txBlobExample } from './common'
import { blake2bFinal, blake2bInit, blake2bUpdate } from 'blakejs'

// @ts-expect-error
import ed25519 from 'ed25519-supercop'

jest.setTimeout(60000)

// Kadena uses the public key as the address. This address was obtained from a real device configured with Zemu mnemonic (APP_SEED)
const expected_pk = 'de12b5e16b93fe81ca4d70656bee4334f2e40f9f28b9796e792d28f2cead74ad'

describe('Standard', function () {
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const nav = zondaxMainmenuNavigation(m.name, [1, 0, 0, 4, -5])
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, nav.schedule)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get app version', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())
      try {
        const resp = await app.getVersion()
        console.log(resp)

        expect(resp).toHaveProperty('testMode')
        expect(resp).toHaveProperty('major')
        expect(resp).toHaveProperty('minor')
        expect(resp).toHaveProperty('patch')
      } catch {
        console.log('getVersion error')
      }
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())

      try {
        const resp = await app.getAddressAndPubKey(PATH, false)

        console.log(resp)
        console.log(resp.pubkey.toString('hex'))
        console.log(resp.address)

        // The address is not checked because the public key is used as an address in the app
        expect(resp.pubkey.toString('hex')).toEqual(expected_pk)
      } catch {
        console.log('getAddress error')
      }
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new KadenaApp(sim.getTransport())

      const respRequest = app.getAddressAndPubKey(PATH, true)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address`)

      const resp = await respRequest
      console.log(resp)

      // The address is not checked because the public key is used as an address in the app
      expect(resp.pubkey.toString('hex')).toEqual(expected_pk)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show address - reject', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new KadenaApp(sim.getTransport())

      const respRequest = app.getAddressAndPubKey(PATH, true)

      expect(respRequest).rejects.toMatchObject({
        returnCode: 0x6986,
        errorMessage: 'Transaction rejected',
      })

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      try {
        await sim.compareSnapshotsAndReject('.', `${m.prefix.toLowerCase()}-show_address_reject`)
      } finally {
      }
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign tx normal', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new KadenaApp(sim.getTransport())

      const txBlob = Buffer.from(txBlobExample)
      const responseAddr = await app.getAddressAndPubKey(PATH, false)
      const pubKey = responseAddr.pubkey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(PATH, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_tx_normal`)

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
