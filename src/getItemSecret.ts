import { PasswordManagerClient } from './passwordManagerClient'
import { getSecureField, isSecureFieldName } from './utils/secureField'
import { SecureFieldName } from './types'
import { InvalidSecureFieldError } from './errors'
import { decryptSecureField } from './encryptSecureField'

/**
 * @see {@link PasswordManagerClient.getItemSecret}
 */
export async function getItemSecret(
  this: PasswordManagerClient,
  vaultId: string,
  itemId: string,
  fieldName: SecureFieldName,
): Promise<string | undefined> {
  return await this.withSessionCredentials(async (keyDerivingKey, password) => {
    const { items } = await this.getVault(vaultId, keyDerivingKey, password)

    if (!isSecureFieldName(fieldName)) {
      throw new InvalidSecureFieldError(fieldName)
    }

    const item = items.find(({ id }) => id === itemId)
    if (!item) {
      return
    }

    const secureField = getSecureField(item, fieldName)
    if (!secureField) {
      return
    }

    return decryptSecureField(keyDerivingKey, secureField)
  })
}
