import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { VaultNotUnlockedError } from './errors'
import { ItemType, SecureFieldName } from './types'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#addGeneratedPassword', () => {
  it('adds generated password to unlocked vault', async () => {
    const type: ItemType = 'generatedPassword'
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()
    expect(client.isLocked()).toBe(false)

    const { id: itemId } = await client.addGeneratedPassword(vault.id, {
      name: 'name',
      password: 'password',
      notes: 'notes',
    })
    expect(itemId).toBeTruthy()

    // test `getItem`
    await expect(client.getItem(vault.id, itemId)).resolves.toEqual({
      id: itemId,
      type,
      name: 'name',
      password: { createdAt: expect.any(String) as string },
      createdAt: expect.any(String) as string,
      updatedAt: expect.any(String) as string,
    })

    // test `listItems`
    const listResult = await client.listItems(vault.id)
    expect(listResult).toHaveLength(1)
    expect(listResult).toContainEqual({
      id: itemId,
      type,
      name: 'name',
      password: { createdAt: expect.any(String) as string },
      createdAt: expect.any(String) as string,
      updatedAt: expect.any(String) as string,
    })

    // test `getItemSecret`
    await expect(
      client.getItemSecret(vault.id, itemId, SecureFieldName.Notes),
    ).resolves.toEqual('notes')
    await expect(
      client.getItemSecret(vault.id, itemId, SecureFieldName.Password),
    ).resolves.toEqual('password')
  })

  it('fails when vaults are locked', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()
    expect(client.isLocked()).toBe(false)

    client.lock()
    expect(client.isLocked()).toBe(true)

    await expect(
      client.addGeneratedPassword(vault.id, {
        name: 'name',
        password: 'password',
      }),
    ).rejects.toThrow(VaultNotUnlockedError)

    await client.unlock('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)
    await expect(client.listItems(vault.id)).resolves.toHaveLength(0)
  })

  it.todo('retries add if secure vault service has changed')
})
