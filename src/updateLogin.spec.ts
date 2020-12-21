import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { VaultNotUnlockedError, VaultNotFoundError } from './errors'
import { UpdateLoginProps } from './updateLogin'
import { SecureFieldName } from './types'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('update login type', () => {
  it.each([{ url: 'new url' }, { user: 'new user' }])(
    'basic fields update only what is passed in %p',
    async (updateProps: UpdateLoginProps) => {
      await client.register('P@ssw0rd!')
      const vault = await client.createVault('')
      expect(vault.id).toBeTruthy()

      const created = await client.addLogin(vault.id, {
        name: 'name',
        url: 'url',
        user: 'user',
        password: 'password',
        notes: 'notes',
      })

      const updated = await client.updateLogin(
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

  it('updates password', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const created = await client.addLogin(vault.id, {
      name: 'name',
      url: 'url',
      user: 'user',
      password: 'password',
      notes: 'notes',
    })

    const updateProps: UpdateLoginProps = {
      password: 'new password',
    }

    const updated = await client.updateLogin(vault.id, created.id, updateProps)
    expect(updated.updatedAt).not.toEqual(created.updatedAt)
    expect(updated).toEqual({
      ...created,
      password: {
        createdAt: expect.any(String) as string,
        replacedAt: updated.updatedAt,
      },
      updatedAt: updated.updatedAt,
    })

    await expect(
      client.getItemSecret(vault.id, created.id, SecureFieldName.Password),
    ).resolves.toEqual('new password')
  })

  it('updates notes', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const created = await client.addLogin(vault.id, {
      name: 'name',
      url: 'url',
      user: 'user',
      password: 'password',
      notes: 'notes',
    })

    const updateProps: UpdateLoginProps = {
      notes: 'new notes',
    }

    const updated = await client.updateLogin(vault.id, created.id, updateProps)
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

    const created = await client.addLogin(vault.id, {
      name: 'name',
      url: 'url',
      user: 'user',
      password: 'password',
      notes: 'notes',
    })

    const updateProps: UpdateLoginProps = {
      user: undefined,
      password: undefined,
      url: undefined,
      notes: undefined,
    }

    const updated = await client.updateLogin(vault.id, created.id, updateProps)
    expect(updated.updatedAt).not.toEqual(created.updatedAt)
    expect(updated).toEqual({
      ...created,
      ...updateProps,
      updatedAt: updated.updatedAt,
    })

    await expect(
      client.getItemSecret(vault.id, created.id, SecureFieldName.Password),
    ).resolves.toBeUndefined()
  })

  it('fails when vault does not exist', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    await client.deleteVault(vault.id)

    await expect(client.updateLogin(vault.id, '42', { name: '....' })) //
      .rejects.toThrow(VaultNotFoundError)
  })

  it('fails when vaults are locked', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    client.lock()
    await expect(client.updateLogin(vault.id, '42', { name: '....' })) //
      .rejects.toThrow(VaultNotUnlockedError)
  })

  it.todo('retries update if secure vault service has changed')
})
