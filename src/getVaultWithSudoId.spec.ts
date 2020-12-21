import { getVaultWithSudoId } from './getVaultWithSudoId'
import { PasswordManagerVaultMetaData } from './types'

describe('#getVaultWithSudoId', () => {
  it('returns a sudo id', () => {
    const vault: PasswordManagerVaultMetaData = {
      id: 'vaultId',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      version: 1,
      owners: [{ id: 'ownerId', issuer: 'sudoplatform.sudoservice' }],
    }
    expect(getVaultWithSudoId(vault)).toEqual('ownerId')
  })

  it('does not find a owner id', () => {
    const vault: PasswordManagerVaultMetaData = {
      id: 'vaultId',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      version: 1,
      owners: [{ id: 'ownerId', issuer: 'sudoplatform.otherservice' }],
    }
    const vault2: PasswordManagerVaultMetaData = {
      id: 'vaultId',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      version: 1,
      owners: [],
    }
    expect(getVaultWithSudoId(vault)).toBeUndefined
    expect(getVaultWithSudoId(vault2)).toBeUndefined
  })
})
