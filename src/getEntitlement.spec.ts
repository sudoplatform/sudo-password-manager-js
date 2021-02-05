import { PasswordManagerClient } from './passwordManagerClient'
import { Entitlement } from './types'
import { getMockClient } from './utils/testing/mockClient'

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#getEntitlement', () => {
  it('returns a entitlement with a vault limit', async () => {
    await client.register('P@ssw0rd!')
    const expected: Entitlement = { name: 'vaultMaxPerSudo', limit: 3 }
    const result = await client.getEntitlement()
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual(expected)
  })
})
