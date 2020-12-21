import { PasswordManagerVault } from './types'
import { IncorrectPasswordOrSecretCodeError } from './errors'
import {
  NotAuthorizedError,
  VersionMismatchError,
} from '@sudoplatform/sudo-common'
import { PasswordManagerClient } from './passwordManagerClient'
import {
  PasswordManagerVaultFormat,
  schemaVaultToBlob,
  vaultToSchemaVault,
} from './vaultBlob'

export async function updateVault(
  this: PasswordManagerClient,
  vaultId: string,
  keyDerivingKey: ArrayBuffer,
  password: ArrayBuffer,
  update: (vault: PasswordManagerVault) => void,
): Promise<void> {
  let retry = 0

  while (true) {
    // Fetch the latest vault from the secure vault service.
    const vault = await this.getVault(vaultId, keyDerivingKey, password)

    // Apply our update to the vault.
    update(vault)

    // Attempt to update the vault on the secure vault service.
    try {
      await this.secureVaultClient.updateVault(
        keyDerivingKey,
        password,
        vault.id,
        vault.version,
        schemaVaultToBlob(vaultToSchemaVault(vault)),
        PasswordManagerVaultFormat,
      )
      break
    } catch (error) {
      if (error instanceof NotAuthorizedError) {
        throw new IncorrectPasswordOrSecretCodeError()
      }
      if (error instanceof VersionMismatchError && retry < 3) {
        // Try again. This will fetch the latest vault and re-apply our change.
        retry++
        continue
      }
      throw error
    }
  }
}
