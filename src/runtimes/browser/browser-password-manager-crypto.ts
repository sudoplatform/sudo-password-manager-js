import {
  PasswordManagerCryptoProvider,
  SessionEncryptedVaultCredentials,
} from '../types'

/**
 * An implementation of `PasswordManagerCryptoProvider` using browser APIs.
 * @see PasswordManagerCryptoProvider
 */
export const passwordManagerCryptoProvider: PasswordManagerCryptoProvider = {
  generateKeyDerivingKey: async (): Promise<ArrayBuffer> => {
    return await crypto.subtle.exportKey(
      'raw',
      await crypto.subtle.generateKey({ name: 'AES-CBC', length: 128 }, true, [
        'encrypt',
      ]),
    )
  },
  hashSubject: async (subject: string): Promise<string> => {
    const digest = await crypto.subtle.digest(
      'SHA-1',
      new TextEncoder().encode(subject),
    )
    return Array.from(new Uint8Array(digest))
      .map((value) => value.toString(16).padStart(2, '0'))
      .join('')
  },
  encryptSessionData: async (
    password: ArrayBuffer,
  ): Promise<SessionEncryptedVaultCredentials> => {
    const sessionKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    )

    const passwordIV = crypto.getRandomValues(new Uint8Array(12))
    const sessionPassword = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: passwordIV },
      sessionKey,
      password,
    )

    return {
      sessionKey,
      password: sessionPassword,
      passwordIV,
    }
  },
  decryptSessionData: async (
    sessionData: SessionEncryptedVaultCredentials,
  ): Promise<{ password: ArrayBuffer }> => {
    if (!(sessionData.sessionKey instanceof CryptoKey))
      throw new TypeError('session key must be a WebCrypto CryptoKey')

    const password = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: sessionData.passwordIV },
      sessionData.sessionKey,
      sessionData.password,
    )

    return { password }
  },
  encryptSecureField: async (
    keyDerivingKey_: ArrayBuffer,
    plaintext: ArrayBuffer,
  ): Promise<ArrayBuffer> => {
    const key = await crypto.subtle.importKey(
      'raw',
      keyDerivingKey_,
      { name: 'AES-CBC', length: 128 },
      false,
      ['encrypt'],
    )

    const iv = crypto.getRandomValues(new Uint8Array(16))

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      key,
      plaintext,
    )

    // prepend iv to ciphertext
    return new Uint8Array([...iv, ...new Uint8Array(ciphertext)])
  },
  decryptSecureField: async (
    keyDerivingKey_: ArrayBuffer,
    ciphertext_: ArrayBuffer,
  ): Promise<ArrayBuffer> => {
    const key = await crypto.subtle.importKey(
      'raw',
      keyDerivingKey_,
      { name: 'AES-CBC', length: 128 },
      false,
      ['decrypt'],
    )

    const bytes = new Uint8Array(ciphertext_)
    const ivLength = 16
    const [iv, ciphertext] = [bytes.slice(0, ivLength), bytes.slice(ivLength)]

    return await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ciphertext)
  },

  utf8Decode: (buffer: ArrayBuffer): string => new TextDecoder().decode(buffer),
  utf8Encode: (string: string): ArrayBuffer => new TextEncoder().encode(string),
}
