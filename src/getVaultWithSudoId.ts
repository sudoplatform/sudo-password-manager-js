import { PasswordManagerVaultMetaData } from './types'

export function getVaultWithSudoId(
  vault: PasswordManagerVaultMetaData,
): string | undefined {
  return vault.owners.find(
    (owner) => owner.issuer === 'sudoplatform.sudoservice',
  )?.id
}
