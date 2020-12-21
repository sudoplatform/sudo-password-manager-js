import { NotRegisteredError } from '@sudoplatform/sudo-common'
import { PasswordManagerClient } from './passwordManagerClient'
import { getMockClient } from './utils/testing/mockClient'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#getEntitlementState', () => {
  it('returns two sudos with no vaults', async () => {
    await client.register('P@ssw0rd!')
    const entitlementState = await client.getEntitlementState()
    expect(entitlementState).toHaveLength(2)
    expect(entitlementState[0].value).toEqual(0)
    expect(entitlementState[1].value).toEqual(0)
  })

  it('returns entitlement state with one vault assigned to one sudo', async () => {
    await client.register('P@ssw0rd!')

    const vault1 = await client.createVault('sudo1')
    expect(vault1.id).toBeTruthy()
    const entitlementState = await client.getEntitlementState()
    expect(entitlementState).toContainEqual({
      limits: 3,
      name: 'vaultMaxPerSudo',
      sudoId: 'sudo1',
      value: 1,
    })
  })

  it('returns entitlement state with multiple vaults', async () => {
    await client.register('P@ssw0rd!')

    const vault1 = await client.createVault('sudo1')
    expect(vault1.id).toBeTruthy()

    const vault2 = await client.createVault('sudo1')
    expect(vault2.id).toBeTruthy()
    const entitlementState = await client.getEntitlementState()
    expect(entitlementState).toEqual([
      {
        limits: 3,
        name: 'vaultMaxPerSudo',
        sudoId: 'sudo1',
        value: 2,
      },
      {
        limits: 3,
        name: 'vaultMaxPerSudo',
        sudoId: 'sudo2',
        value: 0,
      },
    ])
  })

  it('fails when not registered', async () => {
    await expect(client.getEntitlementState()) //
      .rejects.toThrowError(NotRegisteredError)
  })
})
