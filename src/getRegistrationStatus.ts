import { RegistrationStatus } from './types'
import { PasswordManagerClient } from './passwordManagerClient'

/**
 * @see {@link PasswordManagerClient.getRegistrationStatus}
 */
export async function getRegistrationStatus(
  this: PasswordManagerClient,
): Promise<RegistrationStatus> {
  if (await this.hasKeyDerivingKey()) return RegistrationStatus.Registered

  if (await this.secureVaultClient.isRegistered())
    return RegistrationStatus.SecretCodeRequired

  return RegistrationStatus.Unregistered
}
