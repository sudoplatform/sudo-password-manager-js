import {
  VaultNotUnlockedError,
  IncorrectPasswordOrSecretCodeError,
} from './errors'
import { NotAuthorizedError } from '@sudoplatform/sudo-common'
import { PasswordManagerClient } from './passwordManagerClient'

/**
 * @see {@link PasswordManagerClient.deleteVault}
 */
export async function deleteVault(
  this: PasswordManagerClient,
  vaultId: string,
): Promise<void> {
  if (this.isLocked()) throw new VaultNotUnlockedError()

  let secureVault
  try {
    secureVault = await this.withSessionCredentials(
      (keyDerivingKey, password) =>
        this.secureVaultClient.getVault(keyDerivingKey, password, vaultId),
    )
  } catch (error) {
    if (error instanceof NotAuthorizedError) {
      throw new IncorrectPasswordOrSecretCodeError()
    }
    throw error
  }
  if (!secureVault) return

  await this.secureVaultClient.deleteVault(vaultId)
}
