import { passwordManagerCryptoProvider as cryptoProvider } from './runtimes/node/node-password-manager-crypto'
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from './runtimes/node/node-base64'
import { SecureField } from './gen/schema-types'

/**
 * Encrypts a string using the Key Deriving Key and
 * serializes the ciphertext into a `SecureField` object.
 * @param keyDerivingKey key deriving key to encrypt with
 * @param data data to encrypt
 */
export async function encryptSecureField(
  keyDerivingKey: ArrayBuffer,
  data: string,
): Promise<SecureField> {
  return {
    secureValue: arrayBufferToBase64(
      await cryptoProvider.encryptSecureField(
        keyDerivingKey,
        cryptoProvider.utf8Encode(data),
      ),
    ),
  }
}

/**
 * Decrypts a `SecureField` value into its plaintext value.
 * @param keyDerivingKey key deriving key to decrypt with
 * @param data `SecureField` to decrypt
 */
export async function decryptSecureField(
  keyDerivingKey: ArrayBuffer,
  data: SecureField,
): Promise<string> {
  return cryptoProvider.utf8Decode(
    await cryptoProvider.decryptSecureField(
      keyDerivingKey,
      base64ToArrayBuffer(data.secureValue),
    ),
  )
}
