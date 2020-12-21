import { passwordManagerCryptoProvider as cryptoProvider } from './runtimes/node/node-password-manager-crypto'
import { VaultSchema } from './gen/schema-types'
import { Item, ItemType, PasswordManagerVault } from './types'

export const PasswordManagerVaultFormat =
  'com.sudoplatform.passwordmanager.vault.v1'

/** PasswordManagerVault -> VaultSchema */
export const vaultToSchemaVault = (
  vault: PasswordManagerVault,
): VaultSchema => {
  const itemsByType = vault.items.reduce((accumulator, item) => {
    if (!accumulator[item.type]) {
      accumulator[item.type] = []
    }
    accumulator[item.type].push(item)
    return accumulator
  }, {} as Record<ItemType, Item[]>)

  return { ...itemsByType, schemaVersion: vault.schemaVersion } as VaultSchema
}

/** VaultSchema -> blob */
export const schemaVaultToBlob = (vault: VaultSchema): ArrayBuffer =>
  cryptoProvider.utf8Encode(JSON.stringify(vault))

/** blob -> VaultSchema */
export const blobToSchemaVault = (blob: ArrayBuffer): VaultSchema =>
  // TODO: Validation.
  JSON.parse(cryptoProvider.utf8Decode(blob)) as VaultSchema

/** VaultSchema -> PasswordManagerVault */
export const schemaVaultToVault = (
  vaultData: VaultSchema,
): Pick<PasswordManagerVault, 'items' | 'schemaVersion'> => {
  const items = Object.values(vaultData).reduce((accumulator, value) => {
    if (value instanceof Array) {
      accumulator = [...accumulator, ...value]
    }
    return accumulator
  }, [] as Item[])

  return {
    items,
    schemaVersion: vaultData.schemaVersion,
  }
}

/** VaultSchema + VaultSchema -> VaultSchema */
export const mergeSchemaVaults = (
  vaultA: VaultSchema,
  vaultB: VaultSchema,
): VaultSchema => {
  // If A or B has a newer schema version, a DB migration is needed.
  if (
    vaultA.schemaVersion > vaultB.schemaVersion ||
    vaultB.schemaVersion > vaultA.schemaVersion
  )
    throw new Error("Can't merge vaults; incompatible schema versions.")

  const combined: Record<string, Array<Item>> = {}

  const keys = new Set([...Object.keys(vaultA), ...Object.keys(vaultB)])

  for (const key of keys) {
    const valueA = vaultA[key as keyof VaultSchema] ?? []
    const valueB = vaultB[key as keyof VaultSchema] ?? []
    if (Array.isArray(valueA) && Array.isArray(valueB)) {
      const sortItemsById = (itemA: Item, itemB: Item): number =>
        itemA.id < itemB.id ? -1 : itemA.id > itemB.id ? 1 : 0
      const valueASorted = [...valueA].sort(sortItemsById)
      const valueBSorted = [...valueB].sort(sortItemsById)

      const combinedItems: Item[] = []

      const itA = valueASorted[Symbol.iterator]()
      const itB = valueBSorted[Symbol.iterator]()

      let [currentA, currentB] = [itA.next(), itB.next()]

      while (!currentA.done && !currentB.done) {
        if (currentA.value.id < currentB.value.id) {
          combinedItems.push(currentA.value)
          currentA = itA.next()
        } else if (currentA.value.id > currentB.value.id) {
          combinedItems.push(currentB.value)
          currentB = itB.next()
        } else {
          if (currentA.value.updatedAt > currentB.value.updatedAt) {
            combinedItems.push(currentA.value)
          } else {
            combinedItems.push(currentB.value)
          }
          currentA = itA.next()
          currentB = itB.next()
        }
      }

      if (!currentA.done) combinedItems.push(currentA.value, ...itA)
      if (!currentB.done) combinedItems.push(currentB.value, ...itB)

      combined[key] = combinedItems
    }
  }

  const newVault = (combined as unknown) as VaultSchema
  newVault.schemaVersion = vaultA.schemaVersion

  return newVault
}
