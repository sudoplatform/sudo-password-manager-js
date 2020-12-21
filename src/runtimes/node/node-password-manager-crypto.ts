import * as crypto from 'crypto'
import { TextDecoder, TextEncoder } from 'util'
import {
  PasswordManagerCryptoProvider,
  SessionEncryptedVaultCredentials,
} from '../types'

/**
 * An implementation of `PasswordManagerCryptoProvider` using Node.js crypto APIs.
 * @see PasswordManagerCryptoProvider
 */
export const passwordManagerCryptoProvider: PasswordManagerCryptoProvider = {
  generateKeyDerivingKey: async (): Promise<ArrayBuffer> => {
    return crypto.randomBytes(16)
  },
  hashSubject: async (subject: string): Promise<string> => {
    return crypto.createHash('sha1').update(subject).digest('hex')
  },
  encryptSessionData: async (
    password: ArrayBuffer,
  ): Promise<SessionEncryptedVaultCredentials> => {
    const sessionKey = crypto.createSecretKey(crypto.randomBytes(32))

    const encryptedPassword = aesGCMEncrypt(password, sessionKey)

    return {
      sessionKey,
      password: encryptedPassword.ciphertext,
      passwordIV: encryptedPassword.iv,
    }
  },
  decryptSessionData: async (
    sessionData: SessionEncryptedVaultCredentials,
  ): Promise<{ password: ArrayBuffer }> => {
    if (!(sessionData.sessionKey instanceof crypto.KeyObject))
      throw new TypeError('session key must be a crypto.KeyObject')

    const password = aesGCMDecrypt(
      sessionData.password,
      sessionData.sessionKey,
      sessionData.passwordIV,
    )

    return { password }
  },
  encryptSecureField: async (
    keyDerivingKey_: ArrayBuffer,
    plaintext: ArrayBuffer,
  ): Promise<ArrayBuffer> => {
    const key = crypto.createSecretKey(Buffer.from(keyDerivingKey_))
    const iv = crypto.randomBytes(16)

    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv)

    const result = Buffer.concat([
      cipher.update(new Uint8Array(plaintext)),
      cipher.final(),
    ])

    return new Uint8Array([
      ...new Uint8Array(iv),
      ...new Uint8Array(result.buffer, result.byteOffset, result.byteLength),
    ])
  },
  decryptSecureField: async (
    keyDerivingKey_: ArrayBuffer,
    ciphertext_: ArrayBuffer,
  ): Promise<ArrayBuffer> => {
    const bytes = new Uint8Array(ciphertext_)
    const ivLength = 16
    const [iv, ciphertext] = [bytes.slice(0, ivLength), bytes.slice(ivLength)]

    const key = crypto.createSecretKey(Buffer.from(keyDerivingKey_))

    const decipher = crypto.createDecipheriv(
      'aes-128-cbc',
      key,
      new Uint8Array(iv),
    )

    const result = Buffer.concat([
      decipher.update(new Uint8Array(ciphertext)),
      decipher.final(),
    ])

    return new Uint8Array(result.buffer, result.byteOffset, result.byteLength)
  },
  utf8Decode: (buffer: ArrayBuffer): string => new TextDecoder().decode(buffer),
  utf8Encode: (string: string): ArrayBuffer => new TextEncoder().encode(string),
}

const aesGCMEncrypt = (
  plaintext: ArrayBuffer,
  key: crypto.KeyObject,
): { ciphertext: ArrayBuffer; iv: ArrayBuffer } => {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
    authTagLength: 16,
  })

  // authtag is appended to ciphertext as in WebCrypto
  const result = Buffer.concat([
    cipher.update(new Uint8Array(plaintext)),
    cipher.final(),
    cipher.getAuthTag(),
  ])

  const ciphertext = new Uint8Array(
    result.buffer,
    result.byteOffset,
    result.byteLength,
  )

  return { ciphertext, iv }
}

const aesGCMDecrypt = (
  data: ArrayBuffer,
  key: crypto.KeyObject,
  iv: ArrayBuffer,
): ArrayBuffer => {
  const dataArray = new Uint8Array(data)
  const ivArray = new Uint8Array(iv)

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, ivArray, {
    authTagLength: 16,
  })

  // authtag is appended to ciphertext as in WebCrypto
  const authTagOffset = -16
  const authTag = dataArray.slice(authTagOffset)
  const ciphertext = dataArray.slice(undefined, authTagOffset)

  decipher.setAuthTag(authTag)

  const result = Buffer.concat([decipher.update(ciphertext), decipher.final()])

  return new Uint8Array(result.buffer, result.byteOffset, result.byteLength)
}
