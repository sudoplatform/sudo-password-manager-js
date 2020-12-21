import { passwordManagerCryptoProvider as cryptoProvider } from './runtimes/node/node-password-manager-crypto'
import { PasswordManagerClient } from './passwordManagerClient'
import { RegistrationStatus } from './types'
import { SecureVaultAlreadyRegisteredError } from './local-secure-vault-service'
import { normalizeMasterPassword } from './normalizeMasterPassword'
import { zerofill } from './utils/zerofill'

/**
 * @see {@link PasswordManagerClient.register}
 */
export async function register(
  this: PasswordManagerClient,
  password_: string,
): Promise<void> {
  const registrationStatus = await this.getRegistrationStatus()
  if (registrationStatus === RegistrationStatus.Registered) {
    throw new SecureVaultAlreadyRegisteredError()
  }

  // Trim and normalize the master password.
  const password = this.utf8Encode(normalizeMasterPassword(password_))

  const keyDerivingKey = await cryptoProvider.generateKeyDerivingKey()
  await this.secureVaultClient.register(keyDerivingKey, password)

  // persist the key deriving key
  await this.setKeyDerivingKey(keyDerivingKey)
  zerofill(keyDerivingKey)

  // encrypt session data ("unlocks" the vault)
  await this.setSessionPassword(password)
  zerofill(password)
}
