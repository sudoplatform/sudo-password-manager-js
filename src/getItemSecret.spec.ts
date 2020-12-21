import { getMockClient } from './utils/testing/mockClient'
import {
  VaultNotFoundError,
  VaultNotUnlockedError,
  InvalidSecureFieldError,
} from './errors'
import { SecureFieldName } from './types'

describe('#getItemSecret', () => {
  it('returns secret data for an item', async () => {
    const { client } = getMockClient()
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const name = 'name 🔑'
    const user = 'username 用户名 имя пользователя unit-test@sudoplatform.com'
    const notes = 'my very nice notes 笔记 ноты\ngreat stuff'
    const password = 'password 密码 пароль'

    const { id: itemId } = await client.addLogin(vault.id, {
      url: 'https://sudoplatform.com',
      name,
      notes,
      user,
      password,
    })

    await expect(client.getItem(vault.id, itemId)).resolves.toEqual(
      expect.objectContaining({
        id: itemId,
        type: 'login',
        createdAt: expect.any(String) as string,
        updatedAt: expect.any(String) as string,
        url: 'https://sudoplatform.com',
        name,
        user,
      }),
    )

    const notesSecret = await client.getItemSecret(
      vault.id,
      itemId,
      SecureFieldName.Notes,
    )
    expect(notesSecret).toEqual(notes)

    const passwordSecret = await client.getItemSecret(
      vault.id,
      itemId,
      SecureFieldName.Password,
    )
    expect(passwordSecret).toEqual(password)
  })

  it('returns undefined when secret data does not exist', async () => {
    const { client } = getMockClient()
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const { id: itemId } = await client.addLogin(vault.id, {
      name: 'name',
    })

    const notesSecret = await client.getItemSecret(
      vault.id,
      itemId,
      SecureFieldName.Notes,
    )
    expect(notesSecret).toBeUndefined()

    const passwordSecret = await client.getItemSecret(
      vault.id,
      itemId,
      SecureFieldName.Password,
    )
    expect(passwordSecret).toBeUndefined()
  })

  it('returns undefined when item does not exist', async () => {
    const { client } = getMockClient()
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const notesSecret = await client.getItemSecret(
      vault.id,
      'unit-test-not-exist-item-id',
      SecureFieldName.Notes,
    )
    expect(notesSecret).toBeUndefined()

    const passwordSecret = await client.getItemSecret(
      vault.id,
      'unit-test-not-exist-item-id',
      SecureFieldName.Password,
    )
    expect(passwordSecret).toBeUndefined()
  })

  it('fails when vault does not exist', async () => {
    const { client } = getMockClient()
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const { id: itemId } = await client.addLogin(vault.id, {
      name: 'name',
    })

    await client.deleteVault(vault.id)

    await expect(
      client.getItemSecret(vault.id, itemId, SecureFieldName.Notes),
    ).rejects.toThrowError(VaultNotFoundError)
    await expect(
      client.getItemSecret(vault.id, itemId, SecureFieldName.Password),
    ).rejects.toThrowError(VaultNotFoundError)
  })

  it('fails when vaults are locked', async () => {
    const { client } = getMockClient()
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    const { id: itemId } = await client.addLogin(vault.id, {
      name: 'name',
    })

    client.lock()

    await expect(
      client.getItemSecret(vault.id, itemId, SecureFieldName.Notes),
    ).rejects.toThrowError(VaultNotUnlockedError)
    await expect(
      client.getItemSecret(vault.id, itemId, SecureFieldName.Password),
    ).rejects.toThrowError(VaultNotUnlockedError)
  })

  it('fails when field name is not a secret field name', async () => {
    const { client } = getMockClient()
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')

    await expect(
      client.getItemSecret(vault.id, '42', 'fieldName' as SecureFieldName),
    ).rejects.toThrowError(InvalidSecureFieldError)
  })
})
