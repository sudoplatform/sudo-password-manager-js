import { v4 } from 'uuid'
import { PasswordManagerClient } from './passwordManagerClient'
import {
  SecureField,
  BankAccount as BankAccountItem,
  BankAccountType as BankAccountItemType,
} from './gen/schema-types'
import { BankAccount } from './types'
import { removeSecureFields } from './utils/secureField'
import { encryptSecureField } from './encryptSecureField'

/**
 * @see {@link PasswordManagerClient.addBankAccount}
 */
export interface AddBankAccountProps {
  accountNumber?: string
  accountPin?: string
  accountType?: string
  bankName?: string
  branchAddress?: string
  branchPhone?: string
  ibanNumber?: string
  name: string
  notes?: string
  routingNumber?: string
  swiftCode?: string
}

/**
 * @see {@link PasswordManagerClient.addBankAccount}
 */
export async function addBankAccount(
  this: PasswordManagerClient,
  vaultId: string,
  props: AddBankAccountProps,
): Promise<BankAccount> {
  return await this.withSessionCredentials(async (keyDerivingKey, password) => {
    const id = v4()
    const now = new Date().toISOString()

    const notes: SecureField | undefined = props.notes
      ? await encryptSecureField(keyDerivingKey, props.notes)
      : undefined

    const accountNumber: SecureField | undefined = props.accountNumber
      ? await encryptSecureField(keyDerivingKey, props.accountNumber)
      : undefined

    const accountPin: SecureField | undefined = props.accountPin
      ? await encryptSecureField(keyDerivingKey, props.accountPin)
      : undefined

    const bankAccount: BankAccountItem = {
      ...props,
      accountNumber,
      accountPin,
      notes,
      type: BankAccountItemType.BankAccount,
      createdAt: now,
      updatedAt: now,
      id,
    }

    await this.updateVault(vaultId, keyDerivingKey, password, (vault) => {
      vault.items.push(bankAccount)
    })

    return removeSecureFields(bankAccount)
  })
}
