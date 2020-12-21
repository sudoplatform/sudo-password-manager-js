import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { IncorrectPasswordOrSecretCodeError } from './errors'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#changeMasterPassword', () => {
  it('changes vaults password', async () => {
    await client.register('P@ssw0rd!')

    // sanity check unlock with incorrect password fails and correct succeeds
    await expect(client.unlock('new password')) //
      .rejects.toThrowError(IncorrectPasswordOrSecretCodeError)
    await expect(client.unlock('P@ssw0rd!')) //
      .resolves.toBeUndefined()

    // change the password
    await client.changeMasterPassword('new password')

    // now the new password succeeds and the old one does not
    await expect(client.unlock('new password')) //
      .resolves.toBeUndefined()
    await expect(client.unlock('P@ssw0rd!')) //
      .rejects.toThrowError(IncorrectPasswordOrSecretCodeError)
  })

  it('preserves vault data', async () => {
    await client.register('P@ssw0rd!')

    // create a vault and item within the vault
    const vault = await client.createVault('')
    const { id: itemId } = await client.addLogin(vault.id, {
      user: 'user',
      name: 'name',
    })

    // change the password
    await client.changeMasterPassword('new password')

    // verify that vault data can still be fetched
    await expect(client.getItem(vault.id, itemId)).resolves.toEqual({
      id: itemId,
      type: 'login',
      user: 'user',
      name: 'name',
      createdAt: expect.any(String) as string,
      updatedAt: expect.any(String) as string,
    })
  })

  it('performs unicode normalization', async () => {
    await client.register('P@ssw0rd!')

    const romanNumeral4 = '\u{2163}'
    const latinIV = 'IV'

    await client.changeMasterPassword(`f${romanNumeral4}e`)

    client.lock()

    await expect(client.unlock(`f${latinIV}e`)).resolves.toBeUndefined()
  })
})
