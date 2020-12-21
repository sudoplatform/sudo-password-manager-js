import { getMockClient } from './utils/testing/mockClient'
import { PasswordManagerClient } from './passwordManagerClient'
import { NotRegisteredError } from '@sudoplatform/sudo-common'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#listVaults', () => {
  it('starts out with no vaults', async () => {
    await client.register('P@ssw0rd!')
    await expect(client.listVaults()).resolves.toHaveLength(0)
  })

  it('returns multiple vaults', async () => {
    await client.register('P@ssw0rd!')

    const vault1 = await client.createVault('')
    expect(vault1.id).toBeTruthy()

    const vault2 = await client.createVault('')
    expect(vault2.id).toBeTruthy()

    // vaults appears in list
    const list = await client.listVaults()
    expect(list).toHaveLength(2)
    expect(list).toContainEqual(vault1)
    expect(list).toContainEqual(vault2)

    await client.deleteVault(vault2.id)

    // non-deleted vault appears in list
    const list2 = await client.listVaults()
    expect(list2).toHaveLength(1)
    expect(list2).toContainEqual(vault1)
    expect(list2).not.toContainEqual(vault2)
  })

  it('fails when not registered', async () => {
    await expect(client.listVaults()) //
      .rejects.toThrowError(NotRegisteredError)
  })
})
