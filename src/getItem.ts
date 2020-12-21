import { Item } from './types'
import { PasswordManagerClient } from './passwordManagerClient'
import { removeSecureFields } from './utils/secureField'

/**
 * @see {@link PasswordManagerClient.getItem}
 */
export async function getItem(
  this: PasswordManagerClient,
  vaultId: string,
  itemId: string,
): Promise<Item | undefined> {
  return await this.withSessionCredentials(async (keyDerivingKey, password) => {
    const vault = await this.getVault(vaultId, keyDerivingKey, password)

    const item = vault.items.find(({ id }) => id === itemId)
    if (!item) {
      return
    }
    return removeSecureFields(item)
  })
}
