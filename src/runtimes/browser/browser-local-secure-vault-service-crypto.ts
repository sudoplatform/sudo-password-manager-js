import { LocalSudoSecureVaultClientCryptoProvider } from '../../local-secure-vault-service'
import { NotAuthorizedError } from '@sudoplatform/sudo-common'

export const localSudoSecureVaultClientCryptoProvider: LocalSudoSecureVaultClientCryptoProvider = {
  generateSalts: (): {
    authentication: ArrayBuffer
    encryption: ArrayBuffer
  } => ({
    authentication: window.crypto.getRandomValues(new Uint8Array(8)),
    encryption: window.crypto.getRandomValues(new Uint8Array(8)),
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
    const iv = window.crypto.getRandomValues(new Uint8Array(16))
    return {
      blob: await window.crypto.subtle.encrypt(
        { name: 'AES-CBC', length: 256, iv },
        vaultKey,
        blob,
      ),
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
      return await window.crypto.subtle.decrypt(
        { name: 'AES-CBC', length: 256, iv },
        vaultKey,
        blob,
      )
    } catch (error) {
      if (error instanceof Error && error.name === 'OperationError') {
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
): Promise<CryptoKey> => {
  const importedPassword = await window.crypto.subtle.importKey(
    'raw',
    vaultPassword,
    'PBKDF2',
    false,
    ['deriveBits'],
  )
  const passwordDerivedKeyBuffer = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encryptionSalt,
      iterations: rounds,
      hash: 'SHA-256',
    },
    importedPassword,
    256,
  )
  const vaultKeyBuffer = xorBuffers(passwordDerivedKeyBuffer, keyDerivingKey)

  // The vault data is AES CBC encrypted on the client using
  // an AES 256 bit key (the vault encryption key) and IV.
  const vaultKey = await window.crypto.subtle.importKey(
    'raw',
    vaultKeyBuffer,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )

  return vaultKey
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
