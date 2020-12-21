import { PasswordManagerClient } from './passwordManagerClient'

/**
 * @see {@link PasswordManagerClient.removeItem}
 */
export async function removeItem(
  this: PasswordManagerClient,
  vaultId: string,
  itemId: string,
): Promise<void> {
  return await this.withSessionCredentials(async (keyDerivingKey, password) => {
    await this.updateVault(vaultId, keyDerivingKey, password, (vault) => {
      vault.items = vault.items.filter((item) => item.id !== itemId)
    })
  })
}
