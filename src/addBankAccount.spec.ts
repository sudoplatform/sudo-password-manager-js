import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { VaultNotUnlockedError } from './errors'
import { ItemType, SecureFieldName } from './types'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#addBankAccount', () => {
  it('adds bank account to unlocked vault', async () => {
    const type: ItemType = 'bankAccount'
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()
    expect(client.isLocked()).toBe(false)

    const { id: itemId } = await client.addBankAccount(vault.id, {
      name: 'name',
      bankName: 'bankName',
      accountNumber: 'accountNumber',
      accountPin: 'accountPin',
      notes: 'notes',
    })
    expect(itemId).toBeTruthy()

    // test `getItem`
    await expect(client.getItem(vault.id, itemId)).resolves.toEqual({
      id: itemId,
      type,
      name: 'name',
      bankName: 'bankName',
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
      bankName: 'bankName',
      createdAt: expect.any(String) as string,
      updatedAt: expect.any(String) as string,
    })

    // test `getItemSecret`
    await expect(
      client.getItemSecret(vault.id, itemId, SecureFieldName.Notes),
    ).resolves.toEqual(SecureFieldName.Notes)
    await expect(
      client.getItemSecret(vault.id, itemId, SecureFieldName.AccountNumber),
    ).resolves.toEqual('accountNumber')
    await expect(
      client.getItemSecret(vault.id, itemId, SecureFieldName.AccountPin),
    ).resolves.toEqual('accountPin')
  })

  it('fails when vaults are locked', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()
    expect(client.isLocked()).toBe(false)

    client.lock()
    expect(client.isLocked()).toBe(true)

    await expect(
      client.addBankAccount(vault.id, {
        name: 'name',
      }),
    ).rejects.toThrow(VaultNotUnlockedError)

    await client.unlock('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)
    await expect(client.listItems(vault.id)).resolves.toHaveLength(0)
  })

  it.todo('retries add if secure vault service has changed')
})
