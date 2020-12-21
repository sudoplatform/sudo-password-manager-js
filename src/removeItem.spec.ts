import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { VaultNotUnlockedError, VaultNotFoundError } from './errors'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#removeItem', () => {
  it('removes a created item', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()
    expect(client.isLocked()).toBe(false)

    const { id: itemId } = await client.addLogin(vault.id, {
      name: 'name',
    })
    expect(itemId).toBeTruthy()

    await client.removeItem(vault.id, itemId)

    await expect(client.getItem(vault.id, itemId)).resolves.toBeUndefined()
    await expect(client.listItems(vault.id)).resolves.toHaveLength(0)
  })

  it('fails when vault does not exist', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    await client.deleteVault(vault.id)

    await expect(client.removeItem(vault.id, '....')) //
      .rejects.toThrow(VaultNotFoundError)
  })

  it('fails when vaults are locked', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    client.lock()

    await expect(client.removeItem(vault.id, '....')) //
      .rejects.toThrow(VaultNotUnlockedError)
  })

  it('is idempotent', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()
    expect(client.isLocked()).toBe(false)

    const { id: itemId } = await client.addLogin(vault.id, {
      name: 'name',
    })
    expect(itemId).toBeTruthy()

    await client.removeItem(vault.id, itemId)
    await client.removeItem(vault.id, itemId)
  })

  it.todo('retries removal if secure vault service has changed')
})
