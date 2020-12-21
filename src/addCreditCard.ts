import { v4 } from 'uuid'
import { PasswordManagerClient } from './passwordManagerClient'
import {
  SecureField,
  CreditCard as CreditCardItem,
  CreditCardType as CreditCardItemType,
} from './gen/schema-types'
import { CreditCard } from './types'
import { removeSecureFields } from './utils/secureField'
import { encryptSecureField } from './encryptSecureField'

/**
 * @see {@link PasswordManagerClient.addCreditCard}
 */
export interface AddCreditCardProps {
  cardExpiration?: string
  cardName?: string
  cardNumber?: string
  cardSecurityCode?: string
  cardType?: string
  name: string
  notes?: string
}

/**
 * @see {@link PasswordManagerClient.addCreditCard}
 */
export async function addCreditCard(
  this: PasswordManagerClient,
  vaultId: string,
  props: AddCreditCardProps,
): Promise<CreditCard> {
  return await this.withSessionCredentials(async (keyDerivingKey, password) => {
    const id = v4()
    const now = new Date().toISOString()

    const notes: SecureField | undefined = props.notes
      ? await encryptSecureField(keyDerivingKey, props.notes)
      : undefined

    const cardNumber: SecureField | undefined = props.cardNumber
      ? await encryptSecureField(keyDerivingKey, props.cardNumber)
      : undefined

    const cardSecurityCode: SecureField | undefined = props.cardSecurityCode
      ? await encryptSecureField(keyDerivingKey, props.cardSecurityCode)
      : undefined

    const creditCard: CreditCardItem = {
      ...props,
      cardNumber,
      cardSecurityCode,
      notes,
      type: CreditCardItemType.CreditCard,
      createdAt: now,
      updatedAt: now,
      id,
    }

    await this.updateVault(vaultId, keyDerivingKey, password, (vault) => {
      vault.items.push(creditCard)
    })

    return removeSecureFields(creditCard)
  })
}
