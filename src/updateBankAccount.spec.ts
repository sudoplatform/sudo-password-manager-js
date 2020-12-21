import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { VaultNotUnlockedError, VaultNotFoundError } from './errors'
import { UpdateBankAccountProps } from './updateBankAccount'
import { SecureFieldName } from './types'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('update bank account type', () => {
  it.each([
    { accountType: 'new accountType' },
    { bankName: 'new bankName' },
    { branchAddress: 'new branchAddress' },
    { branchPhone: 'new branchPhone' },
    { ibanNumber: 'new ibanNumber' },
    { routingNumber: 'new routingNumber' },
    { swiftCode: 'new swiftCode' },
  ])(
    'basic fields update only what is passed in %p',
    async (updateProps: UpdateBankAccountProps) => {
      await client.register('P@ssw0rd!')
      const vault = await client.createVault('')
      expect(vault.id).toBeTruthy()

      const created = await client.addBankAccount(vault.id, {
        name: 'name',
        notes: 'notes',
      })

      const updated = await client.updateBankAccount(
        vault.id,
        created.id,
        updateProps,
      )
      expect(updated.updatedAt).not.toEqual(created.updatedAt)
      expect(updated).toEqual({
        ...created,
        ...updateProps,
        updatedAt: updated.updatedAt,
      })
    },
  )

  it('updates account number', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const created = await client.addBankAccount(vault.id, {
      name: 'name',
      notes: 'notes',
    })

    const updateProps: UpdateBankAccountProps = {
      accountNumber: 'new accountNumber',
    }

    const updated = await client.updateBankAccount(
      vault.id,
      created.id,
      updateProps,
    )
    expect(updated.updatedAt).not.toEqual(created.updatedAt)
    expect(updated).toEqual({
      ...created,
      updatedAt: updated.updatedAt,
    })

    await expect(
      client.getItemSecret(vault.id, created.id, SecureFieldName.AccountNumber),
    ).resolves.toEqual('new accountNumber')
  })

  it('updates account pin', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const created = await client.addBankAccount(vault.id, {
      name: 'name',
      notes: 'notes',
    })

    const updateProps: UpdateBankAccountProps = {
      accountPin: 'new accountPin',
    }

    const updated = await client.updateBankAccount(
      vault.id,
      created.id,
      updateProps,
    )
    expect(updated.updatedAt).not.toEqual(created.updatedAt)
    expect(updated).toEqual({
      ...created,
      updatedAt: updated.updatedAt,
    })

    await expect(
      client.getItemSecret(vault.id, created.id, SecureFieldName.AccountPin),
    ).resolves.toEqual('new accountPin')
  })

  it('updates notes', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const created = await client.addBankAccount(vault.id, {
      name: 'name',
      notes: 'notes',
    })

    const updateProps: UpdateBankAccountProps = {
      notes: 'new notes',
    }

    const updated = await client.updateBankAccount(
      vault.id,
      created.id,
      updateProps,
    )
    expect(updated.updatedAt).not.toEqual(created.updatedAt)
    expect(updated).toEqual({
      ...created,
      updatedAt: updated.updatedAt,
    })

    await expect(
      client.getItemSecret(vault.id, created.id, SecureFieldName.Notes),
    ).resolves.toEqual('new notes')
  })

  it('removes when parameter is set to undefined', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const created = await client.addBankAccount(vault.id, {
      name: 'name',
      notes: 'notes',
    })

    const updateProps: UpdateBankAccountProps = {
      notes: undefined,
      accountNumber: undefined,
      accountPin: undefined,
      accountType: undefined,
      bankName: undefined,
      branchAddress: undefined,
      branchPhone: undefined,
      ibanNumber: undefined,
      routingNumber: undefined,
      swiftCode: undefined,
    }

    const updated = await client.updateBankAccount(
      vault.id,
      created.id,
      updateProps,
    )
    expect(updated.updatedAt).not.toEqual(created.updatedAt)
    expect(updated).toEqual({
      ...created,
      ...updateProps,
      updatedAt: updated.updatedAt,
    })

    await expect(
      client.getItemSecret(vault.id, created.id, SecureFieldName.AccountNumber),
    ).resolves.toBeUndefined()

    await expect(
      client.getItemSecret(vault.id, created.id, SecureFieldName.AccountPin),
    ).resolves.toBeUndefined()
  })

  it('fails when vault does not exist', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    await client.deleteVault(vault.id)

    await expect(client.updateBankAccount(vault.id, '42', { name: '....' })) //
      .rejects.toThrow(VaultNotFoundError)
  })

  it('fails when vaults are locked', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    client.lock()
    await expect(client.updateBankAccount(vault.id, '42', { name: '....' })) //
      .rejects.toThrow(VaultNotUnlockedError)
  })

  it.todo('retries update if secure vault service has changed')
})
