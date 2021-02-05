import { PasswordManagerClient } from './passwordManagerClient'
import { Entitlement, EntitlementName } from './types'

export async function getEntitlement(
  this: PasswordManagerClient,
): Promise<Entitlement[]> {
  const type: EntitlementName = 'vaultMaxPerSudo'
  const result = await this.sudoEntitlementsClient.getEntitlements()

  const maxVaultEntitlement = result?.entitlements.find(
    (entitlement) => entitlement.name === 'sudoplatform.vault.vaultMaxPerSudo',
  )
  const entitlement: Entitlement = {
    name: type,
    limit: maxVaultEntitlement?.value ?? 0,
  }
  return [entitlement]
}
