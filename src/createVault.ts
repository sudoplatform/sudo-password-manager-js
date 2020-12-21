import { PasswordManagerClient } from './passwordManagerClient'
import {
  VaultNotUnlockedError,
  IncorrectPasswordOrSecretCodeError,
} from './errors'
import { NotAuthorizedError } from '@sudoplatform/sudo-common'
import { PasswordManagerVaultMetaData } from './types'
import { VaultSchema } from './gen/schema-types'
import { PasswordManagerVaultFormat, schemaVaultToBlob } from './vaultBlob'

/**
 * @see {@link PasswordManagerClient.createVault}
 */
export async function createVault(
  this: PasswordManagerClient,
  sudoId: string,
): Promise<PasswordManagerVaultMetaData> {
  if (this.isLocked()) throw new VaultNotUnlockedError()

  const vault: VaultSchema = {
    schemaVersion: 1,
    login: [],
    generatedPassword: [],
    creditCard: [],
    bankAccount: [],
  }

  try {
    const vaultMetadata = await this.withSessionCredentials(
      async (keyDerivingKey, password) => {
        return await this.secureVaultClient.createVault(
          keyDerivingKey,
          password,
          schemaVaultToBlob(vault),
          PasswordManagerVaultFormat,
          await this.sudoProfilesClient.getOwnershipProof(
            sudoId,
            'sudoplatform.secure-vault.vault',
          ),
        )
      },
    )

    const { id, createdAt, updatedAt, version, owners } = vaultMetadata
    return {
      id,
      createdAt: createdAt.toISOString(),
      updatedAt: updatedAt.toISOString(),
      version,
      owners,
    }
  } catch (error) {
    if (error instanceof NotAuthorizedError) {
      throw new IncorrectPasswordOrSecretCodeError()
    }
    throw error
  }
}
