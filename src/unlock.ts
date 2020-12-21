import { PasswordManagerClient } from './passwordManagerClient'
import { IncorrectPasswordOrSecretCodeError } from './errors'
import { NotAuthorizedError } from '@sudoplatform/sudo-common'
import { normalizeMasterPassword } from './normalizeMasterPassword'
import { zerofill } from './utils/zerofill'

/**
 * @see {@link PasswordManagerClient.unlock}
 */
export async function unlock(
  this: PasswordManagerClient,
  password_: string,
  secretCode?: string,
): Promise<void> {
  this.lock()

  const password = this.utf8Encode(normalizeMasterPassword(password_))
  const parsedKeyDerivingKey = secretCode
    ? new Uint8Array(
        (
          secretCode
            // remove hyphens
            .replace(/-/g, '')
            // remove user subject prefix if present
            .replace(/^.....(................................)$/, '$1')
            // extract hex bytes (two nibbles each)
            .match(/(..)/g) ?? []
        ).map((hex) => parseInt(hex, 16)),
      )
    : await this.unsafeGetKeyDerivingKey()

  // verify if the credentials are correct and cache initial vault list
  try {
    await this.secureVaultClient.listVaults(parsedKeyDerivingKey, password)
  } catch (error) {
    if (error instanceof NotAuthorizedError) {
      throw new IncorrectPasswordOrSecretCodeError()
    }
    throw error
  }

  // persist the key deriving key
  await this.setKeyDerivingKey(parsedKeyDerivingKey)
  zerofill(parsedKeyDerivingKey)

  // encrypt session data ("unlocks" the vault)
  // TODO: Prevent race conditions by versioning by # of calls to `changePassword`
  await this.setSessionPassword(password)
  zerofill(password)
}
