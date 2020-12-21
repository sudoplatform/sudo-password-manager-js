import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { VaultNotUnlockedError, VaultNotFoundError } from './errors'
import { UpdateCreditCardProps } from './updateCreditCard'
import { SecureFieldName } from './types'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('update credit card type', () => {
  it.each([
    { cardExpiration: 'new cardExpiration' },
    { cardName: 'new cardName' },
    { cardType: 'new cardType' },
  ])(
    'basic fields update only what is passed in %p',
    async (updateProps: UpdateCreditCardProps) => {
      await client.register('P@ssw0rd!')
      const vault = await client.createVault('')
      expect(vault.id).toBeTruthy()

      const created = await client.addCreditCard(vault.id, {
        name: 'name',
        notes: 'notes',
      })

      const updated = await client.updateCreditCard(
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

  it('updates card number', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const created = await client.addCreditCard(vault.id, {
      name: 'name',
      notes: 'notes',
    })

    const updateProps: UpdateCreditCardProps = {
      cardNumber: 'new cardNumber',
    }

    const updated = await client.updateCreditCard(
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
      client.getItemSecret(vault.id, created.id, SecureFieldName.CardNumber),
    ).resolves.toEqual('new cardNumber')
  })

  it('updates card security code', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const created = await client.addCreditCard(vault.id, {
      name: 'name',
      notes: 'notes',
    })

    const updateProps: UpdateCreditCardProps = {
      cardSecurityCode: 'new cardSecurityCode',
    }

    const updated = await client.updateCreditCard(
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
      client.getItemSecret(
        vault.id,
        created.id,
        SecureFieldName.CardSecurityCode,
      ),
    ).resolves.toEqual('new cardSecurityCode')
  })

  it('updates notes', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const created = await client.addCreditCard(vault.id, {
      name: 'name',
      notes: 'notes',
    })

    const updateProps: UpdateCreditCardProps = {
      notes: 'new notes',
    }

    const updated = await client.updateCreditCard(
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

    const created = await client.addCreditCard(vault.id, {
      name: 'name',
      notes: 'notes',
    })

    const updateProps: UpdateCreditCardProps = {
      cardExpiration: undefined,
      cardName: undefined,
      cardNumber: undefined,
      cardSecurityCode: undefined,
      cardType: undefined,
    }

    const updated = await client.updateCreditCard(
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
      client.getItemSecret(vault.id, created.id, SecureFieldName.CardNumber),
    ).resolves.toBeUndefined()

    await expect(
      client.getItemSecret(
        vault.id,
        created.id,
        SecureFieldName.CardSecurityCode,
      ),
    ).resolves.toBeUndefined()
  })

  it('fails when vault does not exist', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    await client.deleteVault(vault.id)

    await expect(client.updateCreditCard(vault.id, '42', { name: '....' })) //
      .rejects.toThrow(VaultNotFoundError)
  })

  it('fails when vaults are locked', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    client.lock()
    await expect(client.updateCreditCard(vault.id, '42', { name: '....' })) //
      .rejects.toThrow(VaultNotUnlockedError)
  })

  it.todo('retries update if secure vault service has changed')
})
