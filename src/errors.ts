/**
 * The vault with the specified vault ID was not found. It may have been deleted.
 */
export class VaultNotFoundError extends Error {
  constructor() {
    super('The vault with the specified vault ID was not found.')
    if (Error.captureStackTrace)
      Error.captureStackTrace(this, VaultNotFoundError)
    this.name = 'VaultNotFoundError'
  }
}

/**
 * The operation was unable to be completed because the vault is not unlocked.
 */
export class VaultNotUnlockedError extends Error {
  constructor() {
    super('The vault is not unlocked.')
    if (Error.captureStackTrace)
      Error.captureStackTrace(this, VaultNotUnlockedError)
    this.name = 'VaultNotUnlockedError'
  }
}

/**
 * The operation was unable to be completed because the user's secret code is missing.
 * The user's secret code must be provided to unlock the vault for the first time on this device.
 */
export class VaultSecretCodeNotFoundError extends Error {
  constructor() {
    super('The secret code is missing and must be provided.')
    if (Error.captureStackTrace)
      Error.captureStackTrace(this, VaultSecretCodeNotFoundError)
    this.name = 'VaultSecretCodeNotFoundError'
  }
}

/**
 * The provided password and/or secret code do not match the user's registered credentials.
 */
export class IncorrectPasswordOrSecretCodeError extends Error {
  constructor() {
    super('The provided password and/or secret code is incorrect.')
    if (Error.captureStackTrace)
      Error.captureStackTrace(this, IncorrectPasswordOrSecretCodeError)
    this.name = 'IncorrectPasswordOrSecretCodeError'
  }
}

/**
 * The specified item was not found in the vault data.
 */
export class VaultItemNotFoundError extends Error {
  constructor() {
    super('The specified item was not found in the vault.')
    if (Error.captureStackTrace)
      Error.captureStackTrace(this, VaultItemNotFoundError)
    this.name = 'VaultItemNotFoundError'
  }
}

/**
 * The specified field does not exist or is not a SecureField.
 */
export class InvalidSecureFieldError extends Error {
  constructor(fieldName: string) {
    super(`The specified field '${fieldName}' is not a secure field.`)
    if (Error.captureStackTrace)
      Error.captureStackTrace(this, InvalidSecureFieldError)
    this.name = 'InvalidSecureFieldError'
  }
}
