import { Owner } from '@sudoplatform/sudo-secure-vault/lib/gen/graphqlTypes'

/** Persistent storage for key deriving keys. */
export interface KeyDerivingKeyStore {
  /** Retrieves the key deriving key for the user if it is stored. */
  get(): Promise<ArrayBuffer | undefined>

  /** Replaces the stored key deriving key for the user. */
  set(key: ArrayBuffer | undefined): Promise<void>
}

/**
 * Describes the user's password manager registration status.
 */
export enum RegistrationStatus {
  Unregistered,
  SecretCodeRequired,
  Registered,
}

/**
 * An enum indicating the strength of a password
 */
export enum PasswordStrength {
  VeryWeak,
  Weak,
  Moderate,
  Strong,
  VeryStrong,
}

/**
 * Item secure field names
 */
export enum SecureFieldName {
  Notes = 'notes',
  CardNumber = 'cardNumber',
  CardSecurityCode = 'cardSecurityCode',
  AccountNumber = 'accountNumber',
  AccountPin = 'accountPin',
  Password = 'password',
}

/**
 * Password field metadata
 */
export interface PasswordField {
  createdAt: string
  replacedAt?: string
}

/**
 * Basic metadata for a vault
 */
export interface PasswordManagerVaultMetaData {
  id: string
  createdAt: string
  updatedAt: string
  version: number
  owners: Owner[]
}

/**
 * Full data for a password manager vault
 */
export interface PasswordManagerVault extends PasswordManagerVaultMetaData {
  items: Item[]
  schemaVersion: number
}

/**
 * Item type of the password manager vault item
 */
export type ItemType =
  | 'bankAccount'
  | 'creditCard'
  | 'generatedPassword'
  | 'login'

/**
 * Union of all item types
 */
export type Item = GeneratedPassword | Login | BankAccount | CreditCard

/**
 * Generated Password item type
 */
export interface GeneratedPassword {
  createdAt: string
  id: string
  name: string
  password: PasswordField
  type: 'generatedPassword'
  updatedAt: string
  url?: string
}

/**
 * Login item type
 */
export interface Login {
  createdAt: string
  id: string
  name: string
  password?: PasswordField
  type: 'login'
  updatedAt: string
  url?: string
  user?: string
}

/**
 * Credit Card item type
 */
export interface CreditCard {
  cardExpiration?: string
  cardName?: string
  cardType?: string
  createdAt: string
  id: string
  name: string
  type: 'creditCard'
  updatedAt: string
}

/**
 * Bank Account item type
 */
export interface BankAccount {
  accountType?: string
  bankName?: string
  branchAddress?: string
  branchPhone?: string
  createdAt: string
  ibanNumber?: string
  id: string
  name: string
  routingNumber?: string
  swiftCode?: string
  type: 'bankAccount'
  updatedAt: string
}

/**
 * Entitlement item type
 */
export interface Entitlement {
  name: EntitlementName
  limit: number
}

/**
 * Entitlement State type
 */
export interface EntitlementState {
  sudoId: string
  name: EntitlementName
  limits: number
  value: number
}

/**
 * Entitlement names
 */
export type EntitlementName = 'vaultMaxPerSudo'
