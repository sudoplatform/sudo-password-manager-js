import { PasswordManagerClient } from './passwordManagerClient'
import { Item } from './types'
import { removeSecureFields } from './utils/secureField'

/**
 * @see {@link PasswordManagerClient.listItems}
 */
export async function listItems(
  this: PasswordManagerClient,
  vaultId: string,
): Promise<Item[]> {
  return await this.withSessionCredentials(async (keyDerivingKey, password) => {
    const vault = await this.getVault(vaultId, keyDerivingKey, password)
    return vault.items.map((item) => removeSecureFields(item))
  })
}
