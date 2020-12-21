import { FetchOption } from '@sudoplatform/sudo-profiles'
import { getVaultWithSudoId } from './getVaultWithSudoId'
import { PasswordManagerClient } from './passwordManagerClient'
import { EntitlementName, EntitlementState } from './types'

/**
 * @see {@link PasswordManagerClient.getEntitlementState}
 */
export async function getEntitlementState(
  this: PasswordManagerClient,
): Promise<EntitlementState[]> {
  const entitlementResult = await this.sudoEntitlementsClient.getEntitlements()
  const entitlement = entitlementResult?.entitlements.find(
    (entitlement) => entitlement.name === 'sudoplatform.vault.vaultMaxPerSudo',
  )
  if (!entitlement) return []

  const sudos = await this.sudoProfilesClient.listSudos(FetchOption.RemoteOnly)

  const vaults = await this.listVaults()
  const vaultsWithSudoIds = vaults
    .map((vault) => getVaultWithSudoId(vault))
    .filter((sudoId) => sudoId !== undefined)

  const vaultMap = new Map<string, number>()
  for (const sudoId of vaultsWithSudoIds) {
    if (sudoId) {
      vaultMap.set(sudoId, (vaultMap.get(sudoId) ?? 0) + 1)
    }
  }

  const type: EntitlementName = 'vaultMaxPerSudo'
  const state = []
  for (const sudo of sudos) {
    if (sudo.id) {
      state.push({
        sudoId: sudo.id,
        name: type,
        limits: entitlement.value,
        value: vaultMap.get(sudo.id) ?? 0,
      })
    }
  }

  return state
}
