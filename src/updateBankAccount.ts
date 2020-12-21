import { PasswordManagerClient } from './passwordManagerClient'
import { VaultItemNotFoundError } from './errors'
import { BankAccount as BankAccountItem } from './gen/schema-types'
import { BankAccount } from './types'
import { removeSecureFields } from './utils/secureField'
import { encryptSecureField } from './encryptSecureField'

/**
 * @see {@link PasswordManagerClient.updateBankAccount}
 */
export interface UpdateBankAccountProps {
  accountNumber?: string | undefined
  accountPin?: string | undefined
  accountType?: string | undefined
  bankName?: string | undefined
  branchAddress?: string | undefined
  branchPhone?: string | undefined
  ibanNumber?: string | undefined
  name?: string
  notes?: string | undefined
  routingNumber?: string | undefined
  swiftCode?: string | undefined
}

/**
 * @see {@link PasswordManagerClientInterface.updateBankAccount}
 */
export async function updateBankAccount(
  this: PasswordManagerClient,
  vaultId: string,
  bankAccountId: string,
  props: UpdateBankAccountProps,
): Promise<BankAccount> {
  return await this.withSessionCredentials(async (keyDerivingKey, password) => {
    // Extract and encrypt properties that are stored as SecureFields.
    const { notes, accountPin, accountNumber, ...otherProps } = props
    const toUpdate = {
      ...otherProps,
      ...(props.hasOwnProperty('notes')
        ? {
            notes: notes
              ? await encryptSecureField(keyDerivingKey, notes)
              : undefined,
          }
        : {}),
      ...(props.hasOwnProperty('accountPin')
        ? {
            accountPin: accountPin
              ? await encryptSecureField(keyDerivingKey, accountPin)
              : undefined,
          }
        : {}),
      ...(props.hasOwnProperty('accountNumber')
        ? {
            accountNumber: accountNumber
              ? await encryptSecureField(keyDerivingKey, accountNumber)
              : undefined,
          }
        : {}),
    }

    let result: BankAccountItem
    await this.updateVault(vaultId, keyDerivingKey, password, (vault) => {
      const oldItemIndex = vault.items.findIndex(
        (item) => item.id === bankAccountId,
      )
      if (oldItemIndex < 0) throw new VaultItemNotFoundError()
      const [oldItem] = vault.items.splice(oldItemIndex, 1) as BankAccountItem[]

      const newItem = updateBankAccountItem(oldItem, toUpdate)
      result = newItem
      vault.items.push(newItem)
    })

    // `result` will always be defined when calling updateVault.
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return removeSecureFields(result!)
  })
}

const updateBankAccountItem = (
  oldItem: BankAccountItem,
  newItem: Partial<BankAccountItem>,
): BankAccountItem => {
  const now = new Date().toISOString()

  const bankAccount: BankAccountItem = {
    ...oldItem,
    ...(newItem.name ? { name: newItem.name } : {}),
    ...(newItem.hasOwnProperty('notes') ? { notes: newItem.notes } : {}),
    ...(newItem.hasOwnProperty('accountType')
      ? { accountType: newItem.accountType }
      : {}),
    ...(newItem.hasOwnProperty('bankName')
      ? { bankName: newItem.bankName }
      : {}),
    ...(newItem.hasOwnProperty('branchAddress')
      ? { branchAddress: newItem.branchAddress }
      : {}),
    ...(newItem.hasOwnProperty('branchPhone')
      ? { branchPhone: newItem.branchPhone }
      : {}),
    ...(newItem.hasOwnProperty('ibanNumber')
      ? { ibanNumber: newItem.ibanNumber }
      : {}),
    ...(newItem.hasOwnProperty('routingNumber')
      ? { routingNumber: newItem.routingNumber }
      : {}),
    ...(newItem.hasOwnProperty('swiftCode')
      ? { swiftCode: newItem.swiftCode }
      : {}),
    ...(newItem.hasOwnProperty('accountNumber')
      ? { accountNumber: newItem.accountNumber }
      : {}),
    ...(newItem.hasOwnProperty('accountPin')
      ? { accountPin: newItem.accountPin }
      : {}),
    updatedAt: now,
  }

  return bankAccount
}
