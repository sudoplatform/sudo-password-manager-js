import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { VaultNotUnlockedError } from './errors'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#createVault', () => {
  it('creates a vault', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    // vault is initially unlocked
    expect(client.isLocked()).toBe(false)

    // vault appears in list
    const list = await client.listVaults()
    expect(list).toHaveLength(1)
    expect(list).toEqual([vault])
  })

  it('fails when not registered', async () => {
    await expect(client.createVault('')) //
      .rejects.toThrowError(VaultNotUnlockedError)
  })
})
