import { SudoUserClient } from '@sudoplatform/sudo-user'
import { SudoProfilesClient } from '@sudoplatform/sudo-profiles'
import { SudoEntitlementsClient } from '@sudoplatform/sudo-entitlements'
import {
  SudoSecureVaultClient,
  DefaultSudoSecureVaultClient,
} from '@sudoplatform/sudo-secure-vault'
import { CachingSudoSecureVaultClient } from './cachingSudoSecureVaultClient'
import { LocalSudoSecureVaultClient } from './local-secure-vault-service'
import {
  KeyDerivingKeyStore,
  PasswordStrength,
  PasswordManagerVaultMetaData,
  RegistrationStatus,
  Item,
  BankAccount,
  CreditCard,
  GeneratedPassword,
  Login,
  SecureFieldName,
  EntitlementState,
} from './types'
import { SessionEncryptedVaultCredentials } from './runtimes/types'
import { VaultNotUnlockedError, VaultSecretCodeNotFoundError } from './errors'
import { zerofill } from './utils/zerofill'
import { calculateStrengthOfPassword } from './calculateStrengthOfPassword'
import { changeMasterPassword } from './changeMasterPassword'
import { createVault } from './createVault'
import { deleteVault } from './deleteVault'
import { generatePassword, GeneratePasswordOptions } from './generatePassword'
import { getEntitlementState } from './getEntitlementState'
import { getItem } from './getItem'
import { getRegistrationStatus } from './getRegistrationStatus'
import { getItemSecret } from './getItemSecret'
import { getVault } from './getVault'
import { listItems } from './listItems'
import { listVaults } from './listVaults'
import { passwordManagerCryptoProvider as cryptoProvider } from './runtimes/node/node-password-manager-crypto'
import { register } from './register'
import { removeItem } from './removeItem'
import { showSecretCode } from './showSecretCode'
import { unlock } from './unlock'
import { updateVault } from './updateVault'
import { renderRescueKit, RenderRescueKitProps } from './renderRescueKit'
import { AddBankAccountProps, addBankAccount } from './addBankAccount'
import { addCreditCard, AddCreditCardProps } from './addCreditCard'
import {
  addGeneratedPassword,
  AddGeneratedPasswordProps,
} from './addGeneratedPassword'
import { addLogin, AddLoginProps } from './addLogin'
import { UpdateLoginProps, updateLogin } from './updateLogin'
import {
  updateGeneratedPassword,
  UpdateGeneratedPasswordProps,
} from './updateGeneratedPassword'
import { UpdateCreditCardProps, updateCreditCard } from './updateCreditCard'
import { UpdateBankAccountProps, updateBankAccount } from './updateBankAccount'
import {
  blobToSchemaVault,
  mergeSchemaVaults,
  PasswordManagerVaultFormat,
  schemaVaultToBlob,
} from './vaultBlob'

/** Cache configuration parameters for PasswordManagerClient. */
interface CachingClientConfig {
  cacheDatabaseName?: string
  logBackgroundReconciliationError: (error: unknown) => void
}

/**
 * The PasswordManagerClient provides abstractions on top of `SecureVaultService`:
 * 1. Session management to persist `SecureVaultService` credentials.
 * 2. Interpretation of the blob from the `SecureVaultService` as a
 *    password vault and a nice interface to access/modify said vault.
 *
 * It presents these abstractions in an interface similar to other Sudo Platform
 * product SDKs, even though the underlying mechanisms differ.
 *
 * `PasswordManagerClient` implementations must take great care to minimize
 * the exposure of the user's master password and secret code.
 */
export class PasswordManagerClient {
  /**
   * The secure vault client
   * @ignore
   */
  protected secureVaultClient: SudoSecureVaultClient

  /**
   * The sudo user client
   * @ignore
   */
  protected sudoUserClient: SudoUserClient

  /**
   * The sudo profiles client
   * @ignore
   */
  protected sudoProfilesClient: SudoProfilesClient

  /**
   * The sudo entitlements client
   * @ignore
   */
  protected sudoEntitlementsClient: SudoEntitlementsClient

  /**
   * The PasswordManagerClient keeps track of key deriving keys persisted to disk.
   *
   * Creating a vault or accessing a vault using `createVault` or `unlock` will
   * store the generated/provided key deriving key to disk for the vault.
   *
   * The stored key deriving key can be obtained by the application developer
   * (during onboarding or when the user requests their emergency kit again)
   * using the `showSecretCode` method.
   * @ignore
   */
  #keyDerivingKeyStore: KeyDerivingKeyStore

  /**
   * The PasswordManagerClient keeps in-memory state such as
   * the session key and session encrypted master password.
   *
   * `unlock` initializes this value. lock` clears out this value.
   * These methods are analogous to `signIn` and `signOut` from other SDKs
   * because that they set up state required by all other SDK methods.
   * @ignore
   */
  #sessionData: SessionEncryptedVaultCredentials | undefined

  /**
   * Initializes a new instance of the PasswordManagerClient SDK.
   *
   * @param keyDerivingKeyStore The key deriving key store to use.
   * @param sudoUserClient The sudo user SDK client.
   * @param sudoUserClient The sudo profiles SDK client.
   * @param secureVaultConfig SDK configuration for the secure vault service.
   * If not provided, uses the configuration from `DefaultConfigurationManager`.
   * @param cachingClientConfig Local cache configuration. False to disable.
   */
  constructor(
    keyDerivingKeyStore: KeyDerivingKeyStore,
    sudoUserClient: SudoUserClient,
    sudoProfilesClient: SudoProfilesClient,
    sudoEntitlementsClient: SudoEntitlementsClient,
    secureVaultConfig:
      | ConstructorParameters<typeof DefaultSudoSecureVaultClient>[1]
      | undefined,
    cachingClientConfig: false | CachingClientConfig,
  )

  /**
   * Initializes a new instance of the PasswordManagerClient SDK,
   * using an existing instance of `SudoSecureVaultClient`.
   *
   * @param keyDerivingKeyStore The key deriving key store to use.
   * @param sudoUserClient The sudo user SDK client.
   * @param sudoUserClient The sudo profiles SDK client.
   * @param secureVaultClient The secure vault sdk client.
   */
  constructor(
    keyDerivingKeyStore: KeyDerivingKeyStore,
    sudoUserClient: SudoUserClient,
    sudoProfilesClient: SudoProfilesClient,
    sudoEntitlementsClient: SudoEntitlementsClient,
    secureVaultClient: SudoSecureVaultClient,
  )

  constructor(
    keyDerivingKeyStore: KeyDerivingKeyStore,
    sudoUserClient: SudoUserClient,
    sudoProfilesClient: SudoProfilesClient,
    sudoEntitlementsClient: SudoEntitlementsClient,
    arg3:
      | SudoSecureVaultClient
      | ConstructorParameters<typeof DefaultSudoSecureVaultClient>[1],
    cachingClientConfig?: false | CachingClientConfig,
  ) {
    const isSecureVaultClient = (arg: unknown): arg is SudoSecureVaultClient =>
      !!arg &&
      (arg as SudoSecureVaultClient).listVaultsMetadataOnly !== undefined

    this.#keyDerivingKeyStore = keyDerivingKeyStore
    this.sudoUserClient = sudoUserClient
    this.sudoProfilesClient = sudoProfilesClient
    this.sudoEntitlementsClient = sudoEntitlementsClient

    if (isSecureVaultClient(arg3)) {
      // The caller provided a secure vault client so use it.
      this.secureVaultClient = arg3
    } else if (cachingClientConfig) {
      // Instantiate a CachingSudoSecureVaultClient with the provided config.
      this.secureVaultClient = new CachingSudoSecureVaultClient(
        new DefaultSudoSecureVaultClient(sudoUserClient, arg3),
        new LocalSudoSecureVaultClient({
          databaseName: cachingClientConfig.cacheDatabaseName,
          pbkdfRounds: arg3?.pbkdfRounds,
        }),
        ({ blob: blobA }, { blob: blobB }) => ({
          blob: schemaVaultToBlob(
            mergeSchemaVaults(
              blobToSchemaVault(blobA),
              blobToSchemaVault(blobB),
            ),
          ),
          blobFormat: PasswordManagerVaultFormat,
        }),
        cachingClientConfig.logBackgroundReconciliationError,
      )
    } else {
      // Instantiate a DefaultSudoSecureVaultClient with the provided config.
      this.secureVaultClient = new DefaultSudoSecureVaultClient(
        sudoUserClient,
        arg3,
      )
    }
  }

  /** @ignore */
  protected async setSessionPassword(password: ArrayBuffer): Promise<void> {
    this.#sessionData = await cryptoProvider.encryptSessionData(password)
  }

  /**
   * Calls the given function after decrypting the session master password
   * and retrieving the stored key deriving key.
   *
   * After the function resolves, the secrets are erased from memory.
   *
   * @ignore
   */
  protected async withSessionCredentials<T>(
    action: (keyDerivingKey: ArrayBuffer, password: ArrayBuffer) => Promise<T>,
  ): Promise<T> {
    if (!this.#sessionData) throw new VaultNotUnlockedError()
    const { password } = await cryptoProvider.decryptSessionData(
      this.#sessionData,
    )

    const keyDerivingKey = await this.#keyDerivingKeyStore.get()
    if (!keyDerivingKey) throw new VaultSecretCodeNotFoundError()

    let value: T

    try {
      value = await action(keyDerivingKey, password)
    } finally {
      zerofill(keyDerivingKey)
      zerofill(password)
    }

    return value
  }

  /** @ignore */
  protected utf8Encode(value: string): ArrayBuffer {
    return cryptoProvider.utf8Encode(value)
  }

  /** @ignore */
  protected async setKeyDerivingKey(
    keyDerivingKey: ArrayBuffer,
  ): Promise<void> {
    await this.#keyDerivingKeyStore.set(keyDerivingKey)
  }

  /** @ignore */
  protected async hasKeyDerivingKey(): Promise<boolean> {
    const localKeyDerivingKey = await this.#keyDerivingKeyStore.get()
    const exists = !!localKeyDerivingKey
    if (localKeyDerivingKey) zerofill(localKeyDerivingKey)
    return exists
  }

  /**
   * Returns the stored key deriving key.
   *
   * **NOTE:** The caller of this method _must_ `zerofill` the returned buffer
   * when it is no longer in use.
   * Prefer `withSessionCredentials` which does this automatically.
   * @ignore
   */
  protected async unsafeGetKeyDerivingKey(): Promise<ArrayBuffer> {
    const localKeyDerivingKey = await this.#keyDerivingKeyStore.get()
    if (!localKeyDerivingKey) throw new VaultSecretCodeNotFoundError()
    return localKeyDerivingKey
  }

  /** @ignore */
  protected getVault = getVault

  /**
   * Fetches the vault with the given ID from the secure vault service,
   * applies a caller-provided update function to the vault,
   * then uploads the new vault to the secure vault service.
   *
   * Retries up to 3 times if the upload fails due to `VersionMismatchError`.
   *
   * @ignore
   */
  protected updateVault = updateVault

  /**
   * Locks the vaults. Operations that access vault data will fail until the
   * `unlock` method is called with the vault password.
   */
  public lock(): void {
    this.#sessionData = undefined
  }

  /**
   * If this method returns `true`, then the next operation
   * on a vault will not throw `VaultNotUnlockedError`.
   */
  public isLocked(): boolean {
    return !this.#sessionData
  }

  /**
   * Calculate strength of a password
   *
   * @param password The password string to calculate
   * @returns A `PasswordStrength` indicating the strength of the passed in password
   */
  public static calculateStrengthOfPassword(
    password: string,
  ): PasswordStrength {
    return calculateStrengthOfPassword(password)
  }

  /**
   * Generate a password
   *
   * @param options
   * @see GeneratePasswordOptions
   */
  public static generatePassword(
    options: GeneratePasswordOptions = {},
  ): string {
    return generatePassword(options)
  }

  /**
   * Changes the master password used to unlock the vaults.
   *
   * @param newPassword the new password
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   */
  public changeMasterPassword(newPassword: string): Promise<void> {
    return changeMasterPassword.call(this, newPassword)
  }

  /**
   * Creates a new vault.
   *
   * If the vaults are locked, this method throws. Refer to `isLocked`.
   *
   * @param sudoId The ID of the Sudo that will own this vault.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   * @throws `InsufficientEntitlementError` if this Sudo has reached
   *          the maximum number of vaults it is entitled to.
   * @returns `PasswordManagerVaultMetaData` of the created vault
   */
  public createVault(sudoId: string): Promise<PasswordManagerVaultMetaData> {
    return createVault.call(this, sudoId)
  }

  /**
   * Deletes a vault.
   *
   * If the vaults are locked, this method throws. Refer to `isLocked`.
   *
   * @param vaultId the vault to delete
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   */
  public deleteVault(vaultId: string): Promise<void> {
    return deleteVault.call(this, vaultId)
  }

  /**
   * Returns a single item if the id can be found.
   *
   * @param vaultId vault to get item from
   * @param itemId: id of the item to search for
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   */
  public getItem(vaultId: string, itemId: string): Promise<Item | undefined> {
    return getItem.call(this, vaultId, itemId)
  }

  /**
   * Returns the secret data associated with an item if present.
   *
   * @param vaultId vault to get item from
   * @param itemId id of the item to retrieve secret data for
   * @param fieldName which secret to retrieve
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   * @returns The item's secret data, if found.
   */
  public getItemSecret(
    vaultId: string,
    itemId: string,
    fieldName: SecureFieldName,
  ): Promise<string | undefined> {
    return getItemSecret.call(this, vaultId, itemId, fieldName)
  }

  /**
   * Returns the user registration status for the password manager.
   *
   * @see RegistrationStatus
   */
  public getRegistrationStatus(): Promise<RegistrationStatus> {
    return getRegistrationStatus.call(this)
  }

  /**
   * Returns the full list of items stored in the vault.
   *
   * @param vaultId vault to list items in
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   */
  public listItems(vaultId: string): Promise<Item[]> {
    return listItems.call(this, vaultId)
  }

  /**
   * Fetches metadata for existing vaults.
   */
  public listVaults(): Promise<PasswordManagerVaultMetaData[]> {
    return listVaults.call(this)
  }

  /**
   * Registers the user to use the password manager.
   *
   * A secret code is generated and stored on the device.
   * This code can be shown using `showSecretCode`.
   *
   * The vaults are unlocked after calling this method, and will
   * remain unlocked until `lock` is called. See `isLocked`.
   *
   * @param password Password to use to unlock and access vaults.
   * @throws `SecureVaultAlreadyRegisteredError` if already registered.
   */
  public register(password: string): Promise<void> {
    return register.call(this, password)
  }

  /**
   * Deregisters the user from using the password manager.
   * All password manager data will be deleted.
   */
  public async deregister(): Promise<void> {
    this.lock()
    await this.secureVaultClient.deregister()
    this.reset()
  }

  /**
   * Clears all local password manager state and cached data,
   * signing the user out of the password manager.
   */
  public reset(): void {
    this.lock()
    this.#keyDerivingKeyStore.set(undefined)
    this.secureVaultClient.reset()
  }

  /**
   * Removes the vault item with the specified id.
   *
   * @param vaultId vault to remove item from
   * @param itemId id of the vault to remove
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   */
  public removeItem(vaultId: string, itemId: string): Promise<void> {
    return removeItem.call(this, vaultId, itemId)
  }

  /**
   * Returns the formatted secret code of the user stored on this device.
   *
   * _Note:_ Typically the secret code will be prefixed with a hash that is
   * unique to each user who has logged in on this device. If the user is not
   * logged in, this method will return a secret code prefixed with "00000".
   *
   * @throws `VaultSecretCodeNotFoundError` if secret code is not present locally.
   */
  public showSecretCode(): Promise<string> {
    return showSecretCode.call(this)
  }

  /**
   * Unlocks the vaults.
   * Operations that access vault data will succeed until `lock` is called.
   *
   * If the user's secret code is not already present on this device, then
   * the user's secret code must be provided to this method or it will throw.
   * The user's secret code will then be stored on this device for future use.
   *
   * @param password vault password
   * @param secretCode user's secret code
   * @throws `VaultSecretCodeNotFoundError`
   *         if the user's secret code is not present locally and not provided.
   * @throws `IncorrectPasswordOrSecretCodeError`
   *         if the password or secret code is incorrect.
   */
  public unlock(password: string, secretCode?: string): Promise<void> {
    return unlock.call(this, password, secretCode)
  }

  /**
   * Renders a PDf of the Rescue kit
   *
   * @param props optional properties for rendering the rescue kit.
   * @see {@link RenderRescueKitProps}
   * @returns ArrayBuffer of the filled PDF
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   */
  public renderRescueKit(
    props: RenderRescueKitProps = {},
  ): Promise<ArrayBuffer> {
    return renderRescueKit.call(this, props)
  }

  /**
   * Adds a new bank account item to the vault.
   *
   * @param vaultId vault to add the item to
   * @param props new vault item props to add
   * @returns BankAccount of the new item that was added
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   */
  public addBankAccount(
    vaultId: string,
    props: AddBankAccountProps,
  ): Promise<BankAccount> {
    return addBankAccount.call(this, vaultId, props)
  }

  /**
   * Updates a bank account item in the vault.
   *
   * @param vaultId vault to update item in
   * @param bankAccountId id of the bank account to update
   * @param props the fields to update on the bank account item.
   *              Omitted fields keep their old value.
   *              Set to undefined to remove the field.
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   * @throws `VaultItemNotFoundError` if not unlocked. See `isLocked`.
   */
  public updateBankAccount(
    vaultId: string,
    loginId: string,
    props: UpdateBankAccountProps,
  ): Promise<BankAccount> {
    return updateBankAccount.call(this, vaultId, loginId, props)
  }

  /**
   * Adds a new credit card item to the vault.
   *
   * @param vaultId vault to add the item to
   * @param props new vault item props to add
   * @returns CreditCard of the new item that was added
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   */
  public addCreditCard(
    vaultId: string,
    props: AddCreditCardProps,
  ): Promise<CreditCard> {
    return addCreditCard.call(this, vaultId, props)
  }

  /**
   * Updates a credit card item in the vault.
   *
   * @param vaultId vault to update item in
   * @param creditCardId id of the credit card to update
   * @param props the fields to update on the credit card item.
   *              Omitted fields keep their old value.
   *              Set to undefined to remove the field.
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   * @throws `VaultItemNotFoundError` if not unlocked. See `isLocked`.
   */
  public updateCreditCard(
    vaultId: string,
    loginId: string,
    props: UpdateCreditCardProps,
  ): Promise<CreditCard> {
    return updateCreditCard.call(this, vaultId, loginId, props)
  }

  /**
   * Adds a new generated password item to the vault.
   *
   * @param vaultId vault to add the item to
   * @param props new vault item props to add
   * @returns GeneratedPassword of the new item that was added
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   */
  public addGeneratedPassword(
    vaultId: string,
    props: AddGeneratedPasswordProps,
  ): Promise<GeneratedPassword> {
    return addGeneratedPassword.call(this, vaultId, props)
  }

  /**
   * Updates a generated password item in the vault.
   *
   * @param vaultId vault to update item in
   * @param generatedPasswordId id of the generated password to update
   * @param props the fields to update on the login item.
   *              Omitted fields keep their old value.
   *              Set to undefined to remove the field.
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   * @throws `VaultItemNotFoundError` if not unlocked. See `isLocked`.
   */
  public updateGeneratedPassword(
    vaultId: string,
    loginId: string,
    props: UpdateGeneratedPasswordProps,
  ): Promise<GeneratedPassword> {
    return updateGeneratedPassword.call(this, vaultId, loginId, props)
  }

  /**
   * Adds a new login item to the vault.
   *
   * @param vaultId vault to add the item to
   * @param props new vault item props to add
   * @returns Login of the new item that was added
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   */
  public addLogin(vaultId: string, props: AddLoginProps): Promise<Login> {
    return addLogin.call(this, vaultId, props)
  }

  /**
   * Updates a login item in the vault.
   *
   * @param vaultId vault to update item in
   * @param loginId id of the Login to update
   * @param props the fields to update on the login item.
   *              Omitted fields keep their old value.
   *              Set to undefined to remove the field.
   * @throws `VaultNotFoundError` if no vault with the given ID exists.
   * @throws `VaultNotUnlockedError` if not unlocked. See `isLocked`.
   * @throws `VaultItemNotFoundError` if not unlocked. See `isLocked`.
   */
  public updateLogin(
    vaultId: string,
    loginId: string,
    props: UpdateLoginProps,
  ): Promise<Login> {
    return updateLogin.call(this, vaultId, loginId, props)
  }

  /**
   * Fetches the entitlement state.
   *
   * @throws `NotRegisteredError` if used before registered.
   */
  public getEntitlementState(): Promise<EntitlementState[]> {
    return getEntitlementState.call(this)
  }
}
