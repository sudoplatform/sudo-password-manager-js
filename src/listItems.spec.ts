import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { VaultNotUnlockedError, VaultNotFoundError } from './errors'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#listItems', () => {
  it('lists added credentials', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()
    expect(client.isLocked()).toBe(false)

    await expect(client.listItems(vault.id)).resolves.toHaveLength(0)

    const { id: itemId1 } = await client.addLogin(vault.id, {
      user: 'user',
      name: 'name',
    })

    const listResult = await client.listItems(vault.id)
    expect(listResult).toHaveLength(1)
    expect(listResult).toContainEqual(
      expect.objectContaining({ id: itemId1, type: 'login' }),
    )

    const { id: itemId2 } = await client.addLogin(vault.id, {
      user: 'user',
      name: 'name',
    })

    const listResult2 = await client.listItems(vault.id)
    expect(listResult2).toHaveLength(2)
    expect(listResult2).toContainEqual(
      expect.objectContaining({ id: itemId1, type: 'login' }),
    )
    expect(listResult2).toContainEqual(
      expect.objectContaining({ id: itemId2, type: 'login' }),
    )
  })

  it('fails when vault does not exist', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    await client.deleteVault(vault.id)

    await expect(client.listItems(vault.id)) //
      .rejects.toThrow(VaultNotFoundError)
  })

  it('fails when vaults are locked', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    client.lock()
    expect(client.isLocked()).toBe(true)

    await expect(client.listItems(vault.id)).rejects.toThrow(
      VaultNotUnlockedError,
    )
  })
})
