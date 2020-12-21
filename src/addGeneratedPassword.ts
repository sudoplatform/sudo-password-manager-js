import { v4 } from 'uuid'
import { PasswordManagerClient } from './passwordManagerClient'
import {
  SecureField,
  PasswordField,
  GeneratedPassword as GeneratedPasswordItem,
  GeneratedPasswordType as GeneratedPasswordItemType,
} from './gen/schema-types'
import { GeneratedPassword } from './types'
import { removeSecureFields } from './utils/secureField'
import { encryptSecureField } from './encryptSecureField'

/**
 * @see {@link PasswordManagerClient.addGeneratedPassword}
 */
export interface AddGeneratedPasswordProps {
  name: string
  notes?: string
  url?: string
  password: string
}

/**
 * @see {@link PasswordManagerClient.addGeneratedPassword}
 */
export async function addGeneratedPassword(
  this: PasswordManagerClient,
  vaultId: string,
  props: AddGeneratedPasswordProps,
): Promise<GeneratedPassword> {
  return await this.withSessionCredentials(
    async (keyDerivingKey, sCPassword) => {
      const { name, notes: notesValue, password: passwordValue, url } = props
      const id = v4()
      const now = new Date().toISOString()

      const notes: SecureField | undefined = notesValue
        ? await encryptSecureField(keyDerivingKey, notesValue)
        : undefined

      const password: PasswordField = {
        createdAt: now,
        ...(await encryptSecureField(keyDerivingKey, passwordValue)),
      }

      const generatedPassword: GeneratedPasswordItem = {
        type: GeneratedPasswordItemType.GeneratedPassword,
        name,
        url,
        notes,
        password,
        createdAt: now,
        updatedAt: now,
        id,
      }

      await this.updateVault(vaultId, keyDerivingKey, sCPassword, (vault) => {
        vault.items.push(generatedPassword)
      })

      return removeSecureFields(generatedPassword)
    },
  )
}
