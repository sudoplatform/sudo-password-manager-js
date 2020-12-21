import {
  BankAccount,
  BankAccountType,
  Login,
  LoginType,
  VaultSchema,
} from './gen/schema-types'
import { PasswordManagerVault } from './types'
import {
  blobToSchemaVault,
  mergeSchemaVaults,
  schemaVaultToBlob,
  schemaVaultToVault,
  vaultToSchemaVault,
} from './vaultBlob'

describe('vault blob conversions', () => {
  it('round trips from vault to blob and back', () => {
    const vault: PasswordManagerVault = {
      schemaVersion: 1,
      id: 'some vault',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      version: 5,
      items: [
        {
          id: 'some item',
          type: 'login',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          name: 'some login',
        },
        {
          id: 'some item 2',
          type: 'bankAccount',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          name: 'some account',
        },
      ],
      owners: [{ id: 'some owner', issuer: 'some issuer' }],
    }

    expect(
      schemaVaultToVault(
        blobToSchemaVault(schemaVaultToBlob(vaultToSchemaVault(vault))),
      ),
    ).toEqual({ items: vault.items, schemaVersion: vault.schemaVersion })
  })
})

describe('#mergeSchemaVaults', () => {
  it('merges a nonempty vault with an empty vault', () => {
    // define some vault items
    const bankAccount: BankAccount = {
      type: BankAccountType.BankAccount,
      id: 'ba-a',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      name: 'ba-a',
    }
    const login: Login = {
      type: LoginType.Login,
      id: 'login-a',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      name: 'login-a',
    }

    // vaults to merge
    const vaultA: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [bankAccount],
      creditCard: [],
      generatedPassword: [],
      login: [],
    }
    const vaultB: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [],
      creditCard: [],
      generatedPassword: [],
      login: [login],
    }

    // merge vaults
    const merged = mergeSchemaVaults(vaultA, vaultB)

    // verify result
    const expected: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [bankAccount],
      creditCard: [],
      generatedPassword: [],
      login: [login],
    }
    expect(merged).toEqual(expected)
  })

  it('merges nonempty vault blobs', () => {
    // define some vault items
    const bankAccountA: BankAccount = {
      type: BankAccountType.BankAccount,
      id: 'ba-a',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      name: 'ba-a',
    }
    const bankAccountB: BankAccount = {
      type: BankAccountType.BankAccount,
      id: 'ba-b',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      name: 'ba-b',
    }
    const bankAccountC: BankAccount = {
      type: BankAccountType.BankAccount,
      id: 'ba-c',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      name: 'ba-c',
    }

    // vaults to merge
    const vaultA: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [bankAccountA],
      creditCard: [],
      generatedPassword: [],
      login: [],
    }
    const vaultB: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [bankAccountB, bankAccountC],
      creditCard: [],
      generatedPassword: [],
      login: [],
    }

    // merge vaults
    const merged = mergeSchemaVaults(vaultA, vaultB)

    // verify result
    const expected: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [bankAccountA, bankAccountB, bankAccountC],
      creditCard: [],
      generatedPassword: [],
      login: [],
    }
    expect(merged).toEqual(expected)
  })

  it('chooses latest vault item when deduplicating', () => {
    // define some vault items
    const bankAccountA: BankAccount = {
      type: BankAccountType.BankAccount,
      id: 'ba-a',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      name: 'ba-a',
    }
    const bankAccountB1: BankAccount = {
      type: BankAccountType.BankAccount,
      id: 'ba-b',
      createdAt: '2020-10-20T00:18:05.826Z',
      updatedAt: '2020-10-20T00:18:05.826Z',
      name: 'ba-b',
      bankName: 'Original Bank Name',
    }
    const bankAccountB2: BankAccount = {
      type: BankAccountType.BankAccount,
      id: 'ba-b',
      createdAt: '2020-10-20T00:18:05.826Z',
      updatedAt: '2020-10-21T00:18:05.826Z', // newer
      name: 'ba-b',
      bankName: 'Updated Bank Name',
    }
    const bankAccountC: BankAccount = {
      type: BankAccountType.BankAccount,
      id: 'ba-c',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      name: 'ba-c',
    }

    // vaults to merge
    const vaultA: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [bankAccountA, bankAccountB1],
      creditCard: [],
      generatedPassword: [],
      login: [],
    }
    const vaultB: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [bankAccountB2, bankAccountC],
      creditCard: [],
      generatedPassword: [],
      login: [],
    }

    // merge vaults
    const merged = mergeSchemaVaults(vaultA, vaultB)

    // verify result
    const expected: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [bankAccountA, bankAccountB2, bankAccountC],
      creditCard: [],
      generatedPassword: [],
      login: [],
    }
    expect(merged).toEqual(expected)
  })

  it('preserves unknown item types', () => {
    // define some vault items
    const unknownItem = {
      type: 'test-unknown-item',
      id: 'unknown-a',
      createdAt: '2020-10-20T00:18:05.826Z',
      updatedAt: '2020-10-20T00:18:05.826Z',
      name: 'unknown-a',
      foo: 'bar',
    }
    const bankAccount: BankAccount = {
      type: BankAccountType.BankAccount,
      id: 'ba-a',
      createdAt: '2020-10-20T00:18:05.826Z',
      updatedAt: '2020-10-21T00:18:05.826Z',
      name: 'ba-a',
    }

    // vaults to merge
    const vaultA = {
      schemaVersion: 1,
      bankAccount: [],
      creditCard: [],
      generatedPassword: [],
      login: [],
      unknownItem: [unknownItem],
    }
    const vaultB: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [bankAccount],
      creditCard: [],
      generatedPassword: [],
      login: [],
    }

    // merge vaults
    const merged = mergeSchemaVaults(vaultA, vaultB)

    // verify result
    const expected = {
      schemaVersion: 1,
      bankAccount: [bankAccount],
      creditCard: [],
      generatedPassword: [],
      login: [],
      unknownItem: [unknownItem],
    }
    expect(merged).toEqual(expected)
  })

  it('does not attempt to merge unsupported schema versions', () => {
    // vaults to merge
    const vaultA = {
      schemaVersion: 99,
      futureFieldThatRestructuresSchema: {
        login: [],
      },
      bankAccount: [],
      creditCard: [],
      generatedPassword: [],
      login: [],
    }
    const vaultB: VaultSchema = {
      schemaVersion: 1,
      bankAccount: [],
      creditCard: [],
      generatedPassword: [],
      login: [],
    }

    // merge vaults and verify throws
    try {
      mergeSchemaVaults(vaultA, vaultB)
      fail('Expected mergeSchemaVaults to throw.')
    } catch (error) {
      expect(error).toBeInstanceOf(Error)
      expect(error.message).toContain('schema version')
    }
  })
})
