import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import {
  VaultSecretCodeNotFoundError,
  IncorrectPasswordOrSecretCodeError,
} from './errors'
import { InMemoryKeyDerivingKeyStore } from './runtimes/in-memory-key-deriving-key-store'
import { RegistrationStatus } from './types'

let client: PasswordManagerClient
let keyStore: InMemoryKeyDerivingKeyStore

beforeEach(() => {
  const mockClient = getMockClient()
  keyStore = mockClient.keyDerivingKeyStore
  client = mockClient.client
})

describe('lock/unlock/isLocked', () => {
  test('vaults are unlocked after registering', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)
  })

  test('lock is idempotent', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)

    client.lock()
    expect(client.isLocked()).toBe(true)

    client.lock()
    expect(client.isLocked()).toBe(true)
  })

  test('unlock with correct password succeeds', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)

    client.lock()
    expect(client.isLocked()).toBe(true)

    await client.unlock('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)

    // unlock with correct password is idempotent
    await client.unlock('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)
  })

  test('unlock performs password unicode normalization', async () => {
    const angstrom = '\u{212B}' // Å
    const latinWithRing = '\u{00C5}' // Å
    const latinWithCombiningRing = '\u{0041}\u{030A}' // A + °

    const password1 = `h${angstrom}llo`
    const password2 = `h${latinWithRing}llo`
    const password3 = `h${latinWithCombiningRing}llo`

    await client.register(password1)

    client.lock()

    await client.unlock(password2)
    expect(client.isLocked()).toBe(false)

    client.lock()

    await client.unlock(password3)
    expect(client.isLocked()).toBe(false)
  })

  test('unlock vault with secret code and password', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)

    client.lock()
    expect(client.isLocked()).toBe(true)

    // show the user their secret code (e.g. as part of onboarding)
    const secretCode = await client.showSecretCode()

    // clear key deriving key store to simulate a new device
    keyStore.set(undefined)

    // note that unlocking the vault with only the password fails
    await expect(client.unlock('P@ssw0rd!')).rejects.toThrowError(
      VaultSecretCodeNotFoundError,
    )

    // unlocking with the password and secret code succeeds
    await client.unlock('P@ssw0rd!', secretCode)
    expect(client.isLocked()).toBe(false)
  })

  test('unlock ignores hyphen positions in secret code', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)

    client.lock()
    expect(client.isLocked()).toBe(true)

    const secretCode = await client.showSecretCode()
    keyStore.set(undefined)

    const hyphenChangedCode = `-${secretCode.replace(/-/g, '')}-`

    await client.unlock('P@ssw0rd!', hyphenChangedCode)
    expect(client.isLocked()).toBe(false)
  })

  test.each([
    (string: string): string => string.toUpperCase(),
    (string: string): string => string.toLowerCase(),
  ])('unlock ignores case in secret code', async (changeCase) => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)

    client.lock()
    expect(client.isLocked()).toBe(true)

    const secretCode = await client.showSecretCode()
    keyStore.set(undefined)

    const caseChangedCode = changeCase(secretCode)

    await client.unlock('P@ssw0rd!', caseChangedCode)
    expect(client.isLocked()).toBe(false)
  })

  test('unlock with incorrect password fails', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)

    client.lock()
    expect(client.isLocked()).toBe(true)

    await expect(client.unlock('bad')).rejects.toThrow(
      IncorrectPasswordOrSecretCodeError,
    )
    expect(client.isLocked()).toBe(true)

    await expect(client.unlock('d\u0456tto')).rejects.toThrow(
      IncorrectPasswordOrSecretCodeError,
    )
    expect(client.isLocked()).toBe(true)
  })

  test('unlock unlocked with incorrect password locks vault', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)

    await expect(client.unlock('bad')).rejects.toThrow(
      IncorrectPasswordOrSecretCodeError,
    )
    expect(client.isLocked()).toBe(true)
  })
})

describe('#deregister', () => {
  it('deregisters the user from the secure vault service', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)
    await expect(client.showSecretCode()).resolves.toBeTruthy()
    await expect(client.getRegistrationStatus()).resolves.toBe(
      RegistrationStatus.Registered,
    )

    await client.deregister()

    expect(client.isLocked()).toBe(true)
    await expect(client.showSecretCode()).rejects.toThrowError(
      VaultSecretCodeNotFoundError,
    )
    await expect(client.getRegistrationStatus()).resolves.toBe(
      RegistrationStatus.Unregistered,
    )
  })

  it('is idempotent', async () => {
    client.deregister()
    expect(client.isLocked()).toBe(true)
    await expect(client.showSecretCode()).rejects.toThrowError(
      VaultSecretCodeNotFoundError,
    )
    await expect(client.getRegistrationStatus()).resolves.toBe(
      RegistrationStatus.Unregistered,
    )
  })
})

describe('#reset', () => {
  it('resets local data', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)
    await expect(client.showSecretCode()).resolves.toBeTruthy()
    await expect(client.getRegistrationStatus()).resolves.toBe(
      RegistrationStatus.Registered,
    )

    client.reset()

    expect(client.isLocked()).toBe(true)
    await expect(client.showSecretCode()).rejects.toThrowError(
      VaultSecretCodeNotFoundError,
    )
    await expect(client.getRegistrationStatus()).resolves.toBe(
      RegistrationStatus.Unregistered,
    )
  })

  it('is idempotent', async () => {
    client.reset()
    expect(client.isLocked()).toBe(true)
    await expect(client.showSecretCode()).rejects.toThrowError(
      VaultSecretCodeNotFoundError,
    )
    await expect(client.getRegistrationStatus()).resolves.toBe(
      RegistrationStatus.Unregistered,
    )
  })
})
