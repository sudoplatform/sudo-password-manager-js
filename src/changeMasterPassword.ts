import {
  VaultNotUnlockedError,
  IncorrectPasswordOrSecretCodeError,
} from './errors'
import { NotAuthorizedError } from '@sudoplatform/sudo-common'
import { PasswordManagerClient } from './passwordManagerClient'
import { normalizeMasterPassword } from './normalizeMasterPassword'
import { zerofill } from './utils/zerofill'

/**
 * @see {@link PasswordManagerClient.createVault}
 */
export async function changeMasterPassword(
  this: PasswordManagerClient,
  newPassword_: string,
): Promise<void> {
  if (this.isLocked()) throw new VaultNotUnlockedError()

  const newPassword = this.utf8Encode(normalizeMasterPassword(newPassword_))

  try {
    await this.withSessionCredentials((keyDerivingKey, password) =>
      this.secureVaultClient.changeVaultPassword(
        keyDerivingKey,
        password,
        newPassword,
      ),
    )
  } catch (error) {
    if (error instanceof NotAuthorizedError) {
      throw new IncorrectPasswordOrSecretCodeError()
    }
    throw error
  }

  await this.setSessionPassword(newPassword)
  zerofill(newPassword)
}
