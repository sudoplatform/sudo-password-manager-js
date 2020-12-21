import { PasswordManagerClient } from './passwordManagerClient'
import { VaultItemNotFoundError } from './errors'
import { Login as LoginItem, SecureField } from './gen/schema-types'
import { Login } from './types'
import { removeSecureFields } from './utils/secureField'
import { encryptSecureField } from './encryptSecureField'

/**
 * @see {@link PasswordManagerClient.updateLogin}
 */
export interface UpdateLoginProps {
  name?: string
  notes?: string | undefined
  password?: string | undefined
  url?: string | undefined
  user?: string | undefined
}

/**
 * @see {@link PasswordManagerClientInterface.updateLogin}
 */
export async function updateLogin(
  this: PasswordManagerClient,
  vaultId: string,
  loginId: string,
  props: UpdateLoginProps,
): Promise<Login> {
  return await this.withSessionCredentials(
    async (keyDerivingKey, sCPassword) => {
      const { notes, password, ...otherProps } = props
      const toUpdate = {
        ...otherProps,
        ...(props.hasOwnProperty('notes')
          ? {
              notes: notes
                ? await encryptSecureField(keyDerivingKey, notes)
                : undefined,
            }
          : {}),
        ...(props.hasOwnProperty('password')
          ? {
              password: password
                ? await encryptSecureField(keyDerivingKey, password)
                : undefined,
            }
          : {}),
      }

      let result: LoginItem
      await this.updateVault(vaultId, keyDerivingKey, sCPassword, (vault) => {
        const oldItemIndex = vault.items.findIndex(
          (item) => item.id === loginId,
        )
        if (oldItemIndex < 0) throw new VaultItemNotFoundError()
        const [oldItem] = vault.items.splice(oldItemIndex, 1) as LoginItem[]

        const newItem = updateLoginItem(oldItem, toUpdate)
        result = newItem
        vault.items.push(newItem)
      })

      // `result` will always be defined when calling updateVault.
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      return removeSecureFields(result!)
    },
  )
}

const updateLoginItem = (
  oldItem: LoginItem,
  newItem: Omit<Partial<LoginItem>, 'password'> & { password?: SecureField },
): LoginItem => {
  const now = new Date().toISOString()

  const login: LoginItem = {
    ...oldItem,
    ...(newItem.name ? { name: newItem.name } : {}),
    ...(newItem.hasOwnProperty('url') ? { url: newItem.url } : {}),
    ...(newItem.hasOwnProperty('user') ? { user: newItem.user } : {}),
    ...(newItem.hasOwnProperty('password')
      ? {
          password: newItem.password
            ? {
                createdAt: oldItem.password?.createdAt ?? now,
                ...(oldItem.password ? { replacedAt: now } : {}),
                ...newItem.password,
              }
            : undefined,
        }
      : {}),
    ...(newItem.hasOwnProperty('notes') ? { notes: newItem.notes } : {}),
    updatedAt: now,
  }

  return login
}
