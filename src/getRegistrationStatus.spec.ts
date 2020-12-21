import { RegistrationStatus } from './types'
import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { InMemoryKeyDerivingKeyStore } from './runtimes/in-memory-key-deriving-key-store'

let client: PasswordManagerClient
let keyStore: InMemoryKeyDerivingKeyStore

beforeEach(() => {
  const mockClient = getMockClient()
  keyStore = mockClient.keyDerivingKeyStore
  client = mockClient.client
})

describe('#getRegistrationStatus', () => {
  it('starts out Unregistered', async () => {
    await expect(client.getRegistrationStatus()) //
      .resolves.toEqual(RegistrationStatus.Unregistered)
  })

  it('becomes Registered upon registration', async () => {
    await client.register('P@ssw0rd!')

    await expect(client.getRegistrationStatus()) //
      .resolves.toEqual(RegistrationStatus.Registered)
  })

  it('remains Registered when vaults are locked', async () => {
    await client.register('P@ssw0rd!')
    client.lock()

    await expect(client.getRegistrationStatus()) //
      .resolves.toEqual(RegistrationStatus.Registered)
  })

  it('returns SecretCodeRequired on new device', async () => {
    await client.register('P@ssw0rd!')
    client.lock()
    keyStore.set(undefined)

    await expect(client.getRegistrationStatus()) //
      .resolves.toEqual(RegistrationStatus.SecretCodeRequired)
  })

  it('becomes Registered after providing secret code', async () => {
    await client.register('P@ssw0rd!')
    client.lock()

    const secretCode = await client.showSecretCode()
    keyStore.set(undefined)

    await client.unlock('P@ssw0rd!', secretCode)

    await expect(client.getRegistrationStatus()) //
      .resolves.toEqual(RegistrationStatus.Registered)
  })
})
