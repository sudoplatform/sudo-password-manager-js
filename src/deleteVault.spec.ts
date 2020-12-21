import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { VaultNotUnlockedError } from './errors'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#deleteVault', () => {
  it('deletes a created vault', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    await client.deleteVault(vault.id)

    // vault no longer appears in list
    await expect(client.listVaults()).resolves.toHaveLength(0)
  })

  it('delete is idempotent', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    await client.deleteVault(vault.id)

    await client.deleteVault(vault.id)
  })

  it('fails when not registered', async () => {
    await expect(client.deleteVault('aaa')) //
      .rejects.toThrowError(VaultNotUnlockedError)
  })
})
