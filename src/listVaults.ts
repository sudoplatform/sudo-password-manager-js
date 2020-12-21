import { PasswordManagerClient } from './passwordManagerClient'
import { PasswordManagerVaultMetaData } from './types'

/**
 * @see {@link PasswordManagerClient.listVaults}
 */
export async function listVaults(
  this: PasswordManagerClient,
): Promise<PasswordManagerVaultMetaData[]> {
  const vaults = await this.secureVaultClient.listVaultsMetadataOnly()
  return vaults.map(({ id, createdAt, updatedAt, version, owners }) => ({
    id,
    version,
    createdAt: createdAt.toISOString(),
    updatedAt: updatedAt.toISOString(),
    owners,
  }))
}
