import { PasswordManagerVault } from './types'
import {
  VaultNotUnlockedError,
  IncorrectPasswordOrSecretCodeError,
  VaultNotFoundError,
} from './errors'
import { PasswordManagerClient } from './passwordManagerClient'
import {
  blobToSchemaVault,
  schemaVaultToVault,
  PasswordManagerVaultFormat,
} from './vaultBlob'
import { NotAuthorizedError } from '@sudoplatform/sudo-common'

/**
 * Returns a decrypted vault
 * @param vaultId The id of the vault to return
 */
export async function getVault(
  this: PasswordManagerClient,
  vaultId: string,
  keyDerivingKey: ArrayBuffer,
  password: ArrayBuffer,
): Promise<PasswordManagerVault> {
  if (this.isLocked()) throw new VaultNotUnlockedError()

  let secureVault
  try {
    secureVault = await this.secureVaultClient.getVault(
      keyDerivingKey,
      password,
      vaultId,
    )
  } catch (error) {
    if (error instanceof NotAuthorizedError) {
      throw new IncorrectPasswordOrSecretCodeError()
    }
    throw error
  }
  if (!secureVault) throw new VaultNotFoundError()

  const { blob, ...vaultMetadata } = secureVault

  switch (vaultMetadata.blobFormat) {
    case PasswordManagerVaultFormat: /* fall through */
    default: {
      const vault: PasswordManagerVault = {
        ...schemaVaultToVault(blobToSchemaVault(blob)),
        id: vaultMetadata.id,
        createdAt: vaultMetadata.createdAt.toISOString(),
        updatedAt: vaultMetadata.updatedAt.toISOString(),
        version: vaultMetadata.version,
        owners: vaultMetadata.owners,
      }

      return vault
    }
  }
}
