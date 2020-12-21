import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { SecureVaultAlreadyRegisteredError } from './local-secure-vault-service'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#register', () => {
  it('prevents duplicate registration', async () => {
    await client.register('P@ssw0rd!')

    await expect(client.register('P@ssw0rd!')) //
      .rejects.toThrowError(SecureVaultAlreadyRegisteredError)
  })
})
