/**
 * An encrypted master password along with the key used to decrypt it.
 *
 * Intended to reduce the window of time where the user's master password
 * is stored in plaintext within the memory of the JavaScript environment.
 *
 * The key deriving key is not present within this structure in order to
 * reduce the window of time where it is loaded from disk into memory.
 */
export interface SessionEncryptedVaultCredentials {
  sessionKey: unknown
  password: ArrayBuffer
  passwordIV: ArrayBuffer
}

/**
 * Common interface for various platforms such as Node and the browser to
 * implement cryptographic methods required by `password-manager.ts`.
 */
export interface PasswordManagerCryptoProvider {
  /**
   * Securely generates a key deriving key (128-bit AES key) used to
   * authenticate and encrypt within the secure vault service.
   */
  generateKeyDerivingKey: () => Promise<ArrayBuffer>

  /**
   * Returns the hex value of the SHA-1 hash of the given user subject.
   */
  hashSubject: (subject: string) => Promise<string>

  /**
   * Creates a session key and uses it to encrypt the master password.
   */
  encryptSessionData: (
    password: ArrayBuffer,
  ) => Promise<SessionEncryptedVaultCredentials>

  /**
   * Uses the session key within the sessionData to decrypt the master password.
   *
   * All references to the plaintext master password must not be retained
   * beyond the duration of the method that requires it.
   */
  decryptSessionData: (
    sessionData: SessionEncryptedVaultCredentials,
  ) => Promise<{ password: ArrayBuffer }>

  /**
   * Uses the provided `keyDerivingKey` to encrypt the secret data `value`.
   * @returns Concatenation of 16-byte iv and ciphertext.
   */
  encryptSecureField: (
    keyDerivingKey: ArrayBuffer,
    value: ArrayBuffer,
  ) => Promise<ArrayBuffer>

  /**
   * Uses the provided `keyDerivingKey` to decrypt the secret data `value`.
   * @param keyDerivingKey the key deriving key.
   * @param value concatenation of 16-byte iv and ciphertext.
   * @returns Decrypted data.
   */
  decryptSecureField: (
    keyDerivingKey: ArrayBuffer,
    value: ArrayBuffer,
  ) => Promise<ArrayBuffer>

  /**
   * Decodes the contents of the given buffer as a UTF-8 string.
   */
  utf8Decode: (buffer: ArrayBuffer) => string

  /**
   * Encodes the given string as a buffer of UTF-8 data.
   */
  utf8Encode: (string: string) => ArrayBuffer
}
