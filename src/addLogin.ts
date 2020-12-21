import { v4 } from 'uuid'
import { PasswordManagerClient } from './passwordManagerClient'
import {
  SecureField,
  PasswordField,
  Login as LoginItem,
  LoginType as LoginItemType,
} from './gen/schema-types'
import { Login } from './types'
import { removeSecureFields } from './utils/secureField'
import { encryptSecureField } from './encryptSecureField'

/**
 * @see {@link PasswordManagerClient.addLogin}
 */
export interface AddLoginProps {
  name: string
  notes?: string
  url?: string
  user?: string
  password?: string
}

/**
 * @see {@link PasswordManagerClient.addLogin}
 */
export async function addLogin(
  this: PasswordManagerClient,
  vaultId: string,
  props: AddLoginProps,
): Promise<Login> {
  return await this.withSessionCredentials(
    async (keyDerivingKey, sCPassword) => {
      const {
        name,
        notes: notesValue,
        password: passwordValue,
        user,
        url,
      } = props
      const id = v4()
      const now = new Date().toISOString()

      const notes: SecureField | undefined = notesValue
        ? await encryptSecureField(keyDerivingKey, notesValue)
        : undefined

      const password: PasswordField | undefined = passwordValue
        ? {
            createdAt: now,
            ...(await encryptSecureField(keyDerivingKey, passwordValue)),
          }
        : undefined

      const login: LoginItem = {
        type: LoginItemType.Login,
        name,
        url,
        user,
        notes,
        password,
        createdAt: now,
        updatedAt: now,
        id,
      }

      await this.updateVault(vaultId, keyDerivingKey, sCPassword, (vault) => {
        vault.items.push(login)
      })

      return removeSecureFields(login)
    },
  )
}
