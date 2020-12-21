// Initialize IndexedDB mock
require('fake-indexeddb/auto')
// eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-unsafe-assignment
const FDBFactory = require('fake-indexeddb/lib/FDBFactory')

import { PasswordManagerClient } from '../../passwordManagerClient'
import { LocalSudoSecureVaultClient } from '../../local-secure-vault-service'
import { InMemoryKeyDerivingKeyStore } from '../../runtimes/in-memory-key-deriving-key-store'
import { SudoUserClient } from '@sudoplatform/sudo-user'
import { Sudo, SudoProfilesClient } from '@sudoplatform/sudo-profiles'
import { SudoEntitlementsClient } from '@sudoplatform/sudo-entitlements'
import { EntitlementsSet } from '@sudoplatform/sudo-entitlements/lib/gen/graphqlTypes'

type MockSudoUserClient = Partial<SudoUserClient> & {
  getSubject: jest.Mock<string | undefined, []>
}

type MockSudoProfilesClient = Partial<SudoProfilesClient> & {
  getOwnershipProof: jest.Mock<Promise<string>, [string, string]>
  listSudos: jest.Mock<Promise<Sudo[]>, []>
}

type MockSudoEntitlementsClient = Partial<SudoEntitlementsClient> & {
  getEntitlements: jest.Mock<Promise<EntitlementsSet | undefined>, []>
}

export function getMockClient(): {
  client: PasswordManagerClient
  keyDerivingKeyStore: InMemoryKeyDerivingKeyStore
  secureVaultService: LocalSudoSecureVaultClient
  sudoUserClient: MockSudoUserClient
  sudoProfilesClient: MockSudoProfilesClient
  sudoEntitlementsClient: MockSudoEntitlementsClient
} {
  // Use a fresh IndexedDB for each test - required for LocalSudoSecureVaultClient
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
  indexedDB = new FDBFactory()

  // Use a fresh secure vault service for each test
  const secureVaultService = new LocalSudoSecureVaultClient({
    pbkdfRounds: 5000,
  })

  // Use an in-memory key deriving key store
  const keyDerivingKeyStore = new InMemoryKeyDerivingKeyStore()

  // Use a mock SudoUser instance
  const sudoUserClient: MockSudoUserClient = {
    getSubject: jest.fn().mockReturnValue(undefined),
  }

  // Use a mock SudoProfiles instance
  const sudoProfilesClient: MockSudoProfilesClient = {
    getOwnershipProof: jest
      .fn()
      .mockImplementation(
        (sudoId: string) => `${sudoId}:sudoplatform.sudoservice`,
      ),
    listSudos: jest.fn().mockResolvedValue([{ id: 'sudo1' }, { id: 'sudo2' }]),
  }

  // Use a mock SudoEntitlements instance
  const sudoEntitlementsClient: MockSudoEntitlementsClient = {
    getEntitlements: jest.fn().mockReturnValue({
      createdAt: new Date(),
      updatedAt: new Date(),
      version: 1,
      name: 'test',
      description: '',
      entitlements: [
        {
          name: 'sudoplatform.vault.vaultMaxPerSudo',
          description: '',
          value: 3,
        },
      ],
    }),
  }

  // Create the client under test
  const client = new PasswordManagerClient(
    keyDerivingKeyStore,
    sudoUserClient as SudoUserClient,
    sudoProfilesClient as SudoProfilesClient,
    sudoEntitlementsClient as SudoEntitlementsClient,
    secureVaultService,
  )

  return {
    client,
    keyDerivingKeyStore,
    secureVaultService,
    sudoUserClient,
    sudoProfilesClient,
    sudoEntitlementsClient,
  }
}
