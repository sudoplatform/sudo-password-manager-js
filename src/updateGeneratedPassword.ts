import { PasswordManagerClient } from './passwordManagerClient'
import { VaultItemNotFoundError } from './errors'
import {
  GeneratedPassword as GeneratedPasswordItem,
  SecureField,
} from './gen/schema-types'
import { GeneratedPassword } from './types'
import { removeSecureFields } from './utils/secureField'
import { encryptSecureField } from './encryptSecureField'

/**
 * @see {@link PasswordManagerClient.updateGeneratedPassword}
 */
export interface UpdateGeneratedPasswordProps {
  name?: string
  notes?: string | undefined
  password?: string | undefined
  url?: string | undefined
}

/**
 * @see {@link PasswordManagerClientInterface.updateGeneratedPassword}
 */
export async function updateGeneratedPassword(
  this: PasswordManagerClient,
  vaultId: string,
  generatedPasswordId: string,
  props: UpdateGeneratedPasswordProps,
): Promise<GeneratedPassword> {
  return await this.withSessionCredentials(
    async (keyDerivingKey, sCPassword) => {
      // Extract and encrypt properties that are stored as SecureFields.
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

      let result: GeneratedPasswordItem
      await this.updateVault(vaultId, keyDerivingKey, sCPassword, (vault) => {
        const oldItemIndex = vault.items.findIndex(
          (item) => item.id === generatedPasswordId,
        )
        if (oldItemIndex < 0) throw new VaultItemNotFoundError()
        const [oldItem] = vault.items.splice(
          oldItemIndex,
          1,
        ) as GeneratedPasswordItem[]

        const newItem = updateGeneratedPasswordItem(oldItem, toUpdate)
        result = newItem
        vault.items.push(newItem)
      })

      // `result` will always be defined when calling updateVault.
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      return removeSecureFields(result!)
    },
  )
}

const updateGeneratedPasswordItem = (
  oldItem: GeneratedPasswordItem,
  newItem: Omit<Partial<GeneratedPasswordItem>, 'password'> & {
    password?: SecureField
  },
): GeneratedPasswordItem => {
  const now = new Date().toISOString()

  const generatedPassword: GeneratedPasswordItem = {
    ...oldItem,
    ...(newItem.hasOwnProperty('name') ? { name: newItem.name } : {}),
    ...(newItem.hasOwnProperty('notes') ? { notes: newItem.notes } : {}),
    ...(newItem.hasOwnProperty('url') ? { url: newItem.url } : {}),
    ...(newItem.password
      ? {
          password: {
            createdAt: oldItem.password.createdAt,
            replacedAt: now,
            ...newItem.password,
          },
        }
      : {}),
    updatedAt: now,
  }

  return generatedPassword
}
