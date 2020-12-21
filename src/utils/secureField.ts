import { SecureField } from '../gen/schema-types'
import { Item, SecureFieldName } from '../types'

/**
 * Checks if the provided secure field name is actually a secure field name
 *
 * @param secureFieldName The secure field to check
 */
export function isSecureFieldName(
  secureFieldName: unknown,
): secureFieldName is SecureFieldName {
  return Object.values(SecureFieldName).includes(
    secureFieldName as SecureFieldName,
  )
}

/**
 * Checks if the provided secure field is actually a secure field type
 *
 * @param secureField The secure field to check
 */
export function isSecureField(
  secureField: unknown,
): secureField is SecureField {
  if (!secureField) return false
  return !!(secureField as SecureField).secureValue
}

/**
 * Returns the provided secure field from the item.
 *
 * @param item The item to return the secure field for.
 * @param fieldName The secure field to return
 */
export function getSecureField<T>(
  item: T,
  fieldName: SecureFieldName,
): SecureField | undefined {
  const field = item[fieldName as keyof T]
  if (isSecureField(field)) {
    return field
  }
}

/**
 * Remove secure fields from the item
 *
 * If the field type is password it will keep the audit fields inside
 * and just remove the secureValue.
 */
export function removeSecureFields<T extends Item>(item: T): T {
  return Object.entries(item).reduce((accumulator, [fieldName, fieldValue]) => {
    if (!isSecureField(fieldValue)) {
      return {
        ...accumulator,
        [fieldName]: fieldValue,
      }
    }

    if (fieldName === SecureFieldName.Password) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { secureValue: _, ...rest } = fieldValue
      return {
        ...accumulator,
        [fieldName]: rest,
      }
    }

    return accumulator
  }, {} as T)
}
