import { LocalSudoSecureVaultClientCryptoProvider } from '../../local-secure-vault-service'
import { NotAuthorizedError } from '@sudoplatform/sudo-common'
import * as crypto from 'crypto'

export const localSudoSecureVaultClientCryptoProvider: LocalSudoSecureVaultClientCryptoProvider = {
  generateSalts: (): {
    authentication: ArrayBuffer
    encryption: ArrayBuffer
  } => ({
    authentication: crypto.randomBytes(8),
    encryption: crypto.randomBytes(8),
  }),

  encryptVaultBlob: async (
    keyDerivingKey: ArrayBuffer,
    vaultPassword: ArrayBuffer,
    encryptionSalt: ArrayBuffer,
    rounds: number,
    blob: ArrayBuffer,
  ): Promise<{ blob: ArrayBuffer; iv: ArrayBuffer }> => {
    // The vault data is AES CBC encrypted on the client using
    // an AES 256 bit key (the vault encryption key) and IV.
    const vaultKey = await deriveVaultKey(
      keyDerivingKey,
      vaultPassword,
      encryptionSalt,
      rounds,
    )
    const iv = crypto.randomBytes(16)

    const cipher = crypto.createCipheriv('aes-256-cbc', vaultKey, iv)

    const result = Buffer.concat([
      cipher.update(new Uint8Array(blob)),
      cipher.final(),
    ])

    return {
      blob: new Uint8Array(result.buffer, result.byteOffset, result.byteLength),
      iv,
    }
  },

  decryptVaultBlob: async (
    keyDerivingKey: ArrayBuffer,
    vaultPassword: ArrayBuffer,
    encryptionSalt: ArrayBuffer,
    rounds: number,
    iv: ArrayBuffer,
    blob: ArrayBuffer,
  ): Promise<ArrayBuffer> => {
    // The vault data is AES CBC encrypted on the client using
    // an AES 256 bit key (the vault encryption key) and IV.
    try {
      const vaultKey = await deriveVaultKey(
        keyDerivingKey,
        vaultPassword,
        encryptionSalt,
        rounds,
      )

      const decipher = crypto.createDecipheriv(
        'aes-256-cbc',
        vaultKey,
        new Uint8Array(iv),
      )

      const result = Buffer.concat([
        decipher.update(new Uint8Array(blob)),
        decipher.final(),
      ])

      return new Uint8Array(result.buffer, result.byteOffset, result.byteLength)
    } catch (error) {
      if (isDecryptionError(error)) {
        throw new NotAuthorizedError()
      }
      throw error
    }
  },
}

/*
 * The vault encryption key is calculated from the XOR combined result of
 * n rounds of PBKDF2 on the vault password with an encryption salt and the
 * key deriving key.
 */
const deriveVaultKey = async (
  keyDerivingKey: ArrayBuffer,
  vaultPassword: ArrayBuffer,
  encryptionSalt: ArrayBuffer,
  rounds: number,
): Promise<crypto.KeyObject> => {
  // The vault data is AES CBC encrypted on the client using
  // an AES 256 bit key (the vault encryption key) and IV.
  const keyByteLength = 32

  const passwordDerivedKeyBuffer: ArrayBuffer = await new Promise(
    (resolve, reject) => {
      crypto.pbkdf2(
        new Uint8Array(vaultPassword),
        new Uint8Array(encryptionSalt),
        rounds,
        keyByteLength,
        'sha256',
        (error, derivedKey) => {
          if (error) return reject(error)
          resolve(derivedKey.buffer)
        },
      )
    },
  )

  const vaultKeyBuffer = xorBuffers(passwordDerivedKeyBuffer, keyDerivingKey)

  return crypto.createSecretKey(Buffer.from(vaultKeyBuffer))
}

/**
 * xors two ArrayBuffer instances together. The two buffers must have the same size.
 */
const xorBuffers = (
  buffer1: ArrayBuffer,
  buffer2: ArrayBuffer,
): ArrayBuffer => {
  const array1 = new Uint8Array(buffer1)
  const array2 = new Uint8Array(buffer2)
  const result = new Uint8Array(
    Math.max(buffer1.byteLength, buffer2.byteLength),
  )
  for (let i = 0; i < Math.min(buffer1.byteLength, buffer2.byteLength); i++) {
    result[i] = array1[i] ^ array2[i]
  }
  return result
}

interface DecryptionError {
  code: 'ERR_OSSL_EVP_BAD_DECRYPT'
}

const isDecryptionError = (error: unknown): error is DecryptionError =>
  (error as DecryptionError).code === 'ERR_OSSL_EVP_BAD_DECRYPT'
