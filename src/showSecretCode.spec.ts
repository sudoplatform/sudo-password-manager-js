import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { VaultSecretCodeNotFoundError } from './errors'
import { InMemoryKeyDerivingKeyStore } from './runtimes/in-memory-key-deriving-key-store'

let client: PasswordManagerClient
let keyStore: InMemoryKeyDerivingKeyStore

beforeEach(() => {
  const mockClient = getMockClient()
  keyStore = mockClient.keyDerivingKeyStore
  client = mockClient.client
})

describe('#showSecretCode', () => {
  it('shows the secret code after registering', async () => {
    const { client, sudoUserClient } = getMockClient()
    sudoUserClient.getSubject.mockReturnValue('some subject')

    await client.register('P@ssw0rd!')

    const secretCode = await client.showSecretCode()
    expect(secretCode).toMatch(
      /E2527-(......)-(.....)-(.....)-(.....)-(.....)-(......)/,
    )
    expect(secretCode).toBe(secretCode.toUpperCase())
  })

  it('fails when not registered', async () => {
    await expect(client.showSecretCode()).rejects.toThrow(
      VaultSecretCodeNotFoundError,
    )
  })

  it('fails when the secret code is not stored locally', async () => {
    await client.register('P@ssw0rd!')

    // clear the mock key deriving key store
    keyStore.set(undefined)

    await expect(client.showSecretCode()).rejects.toThrow(
      VaultSecretCodeNotFoundError,
    )
  })
})
