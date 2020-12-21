import { PasswordManagerClient } from './passwordManagerClient'
import { VaultItemNotFoundError } from './errors'
import { CreditCard as CreditCardItem } from './gen/schema-types'
import { CreditCard } from './types'
import { removeSecureFields } from './utils/secureField'
import { encryptSecureField } from './encryptSecureField'

/**
 * @see {@link PasswordManagerClient.updateCreditCard}
 */
export interface UpdateCreditCardProps {
  cardExpiration?: string | undefined
  cardName?: string | undefined
  cardNumber?: string | undefined
  cardSecurityCode?: string | undefined
  cardType?: string | undefined
  name?: string
  notes?: string | undefined
}

/**
 * @see {@link PasswordManagerClientInterface.updateCreditCard}
 */
export async function updateCreditCard(
  this: PasswordManagerClient,
  vaultId: string,
  creditCardId: string,
  props: UpdateCreditCardProps,
): Promise<CreditCard> {
  return await this.withSessionCredentials(async (keyDerivingKey, password) => {
    // Extract and encrypt properties that are stored as SecureFields.
    const { notes, cardSecurityCode, cardNumber, ...otherProps } = props
    const toUpdate: Partial<CreditCardItem> = {
      ...otherProps,
      ...(props.hasOwnProperty('notes')
        ? {
            notes: notes
              ? await encryptSecureField(keyDerivingKey, notes)
              : undefined,
          }
        : {}),
      ...(props.hasOwnProperty('cardSecurityCode')
        ? {
            cardSecurityCode: cardSecurityCode
              ? await encryptSecureField(keyDerivingKey, cardSecurityCode)
              : undefined,
          }
        : {}),
      ...(props.hasOwnProperty('cardNumber')
        ? {
            cardNumber: cardNumber
              ? await encryptSecureField(keyDerivingKey, cardNumber)
              : undefined,
          }
        : {}),
    }

    let result: CreditCardItem
    await this.updateVault(vaultId, keyDerivingKey, password, (vault) => {
      const oldItemIndex = vault.items.findIndex(
        (item) => item.id === creditCardId,
      )
      if (oldItemIndex < 0) throw new VaultItemNotFoundError()
      const [oldItem] = vault.items.splice(oldItemIndex, 1) as CreditCardItem[]

      const newItem = updateCreditCardItem(oldItem, toUpdate)
      result = newItem
      vault.items.push(newItem)
    })

    // `result` will always be defined by updateVault's function.
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return removeSecureFields(result!)
  })
}

const updateCreditCardItem = (
  oldItem: CreditCardItem,
  newItem: Partial<CreditCardItem>,
): CreditCardItem => {
  const now = new Date().toISOString()

  const creditCard: CreditCardItem = {
    ...oldItem,
    ...(newItem.name ? { name: newItem.name } : {}),
    ...(newItem.hasOwnProperty('notes') ? { notes: newItem.notes } : {}),
    ...(newItem.hasOwnProperty('cardExpiration')
      ? { cardExpiration: newItem.cardExpiration }
      : {}),
    ...(newItem.hasOwnProperty('cardName')
      ? { cardName: newItem.cardName }
      : {}),
    ...(newItem.hasOwnProperty('cardType')
      ? { cardType: newItem.cardType }
      : {}),
    ...(newItem.hasOwnProperty('cardSecurityCode')
      ? { cardSecurityCode: newItem.cardSecurityCode }
      : {}),
    ...(newItem.hasOwnProperty('cardNumber')
      ? { cardNumber: newItem.cardNumber }
      : {}),
    updatedAt: now,
  }

  return creditCard
}
