import {
  SudoSecureVaultClient,
  InvalidVaultError,
} from '@sudoplatform/sudo-secure-vault'
import {
  NotAuthorizedError,
  NotRegisteredError,
  VersionMismatchError,
} from '@sudoplatform/sudo-common'
import {
  Vault,
  VaultMetadata,
} from '@sudoplatform/sudo-secure-vault/lib/vault/vaultClient'
import { v4 as uuid } from 'uuid'
import { localSudoSecureVaultClientCryptoProvider as cryptoProvider } from './runtimes/node/node-local-secure-vault-service-crypto'

/**
 * Common interface for various platforms such as Node and the browser to
 * implement cryptographic methods required by `LocalSecureVaultService`.
 */
export interface LocalSudoSecureVaultClientCryptoProvider {
  /**
   * Generates 64-bit salts that will be used when deriving keys for the user.
   */
  generateSalts: () => {
    authentication: ArrayBuffer
    encryption: ArrayBuffer
  }

  /**
   * Encrypts a blob representation of a vault.
   */
  encryptVaultBlob: (
    keyDerivingKey: ArrayBuffer,
    vaultPassword: ArrayBuffer,
    encryptionSalt: ArrayBuffer,
    rounds: number,
    blob: ArrayBuffer,
  ) => Promise<{ blob: ArrayBuffer; iv: ArrayBuffer }>

  /**
   * Decrypts an encrypted blob representation of a vault.
   */
  decryptVaultBlob: (
    keyDerivingKey: ArrayBuffer,
    vaultPassword: ArrayBuffer,
    encryptionSalt: ArrayBuffer,
    rounds: number,
    iv: ArrayBuffer,
    blob: ArrayBuffer,
  ) => Promise<ArrayBuffer>
}

/** Registration was unable to be completed since the user is already registered. */
export class SecureVaultAlreadyRegisteredError extends Error {}

interface InitializationData {
  owner: string
  authenticationSalt: ArrayBuffer
  encryptionSalt: ArrayBuffer
  pbkdfRounds: number
}

type RegistrationData = InitializationData & {
  verifier: ArrayBuffer
  verifierIv: ArrayBuffer
}

export type LocalVault<TAdditionalMetadata> = Vault & {
  /** Additional metadata stored with the vault. See {@link setVault}. */
  additionalMetadata: TAdditionalMetadata | undefined
}

type StoredVault<TAdditionalMetadata> = LocalVault<TAdditionalMetadata> & {
  iv: ArrayBuffer
}

export type LocalSudoSecureVaultClientConfig = Partial<{
  /** The name of the IndexedDB database to access. */
  databaseName: string
  /** Number of rounds of PBKDF2 to use to derive vault key from password. */
  pbkdfRounds: number
}>

/**
 * An implementation of the `SecureVaultClient` interface that uses
 * [IndexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API)
 * as its backing data store.
 *
 * Note for NodeJS: To use this class from within NodeJS, you must first polyfill
 * an indexeddb implemention, e.g.:
 *   ```
 *   require('fake-indexeddb/auto')
 *   ```
 */
export class LocalSudoSecureVaultClient implements SudoSecureVaultClient {
  private db: Promise<IDBDatabase>
  private pbkdfRounds: number
  private ownerId = 'some owner'

  constructor({
    databaseName = 'com.sudoplatform.passwordmanager.localvault',
    pbkdfRounds = 100_000,
  }: LocalSudoSecureVaultClientConfig = {}) {
    this.pbkdfRounds = pbkdfRounds
    this.db = new Promise((resolve, reject) => {
      const request = indexedDB.open(databaseName, 1)

      request.onsuccess = () => {
        const db = request.result
        resolve(db)
      }

      request.onerror = () => {
        reject(request.error)
      }

      request.onupgradeneeded = (event) => {
        if (event.oldVersion === 0 && event.newVersion === 1) {
          const db = request.result

          // Migrate DB tables from version 0 to version 1
          db.createObjectStore('vaults', {
            keyPath: 'id',
            autoIncrement: false,
          })
          db.createObjectStore('registration', {
            keyPath: 'owner',
            autoIncrement: false,
          })
        }
      }
    })
  }

  async register(key: ArrayBuffer, password: ArrayBuffer): Promise<string> {
    // Generate salts
    const salts = cryptoProvider.generateSalts()

    // Generate registration verifier (to later check if the user is registered)
    const verifier = await this.computeRegistrationVerifier(
      key,
      password,
      salts.encryption,
      this.pbkdfRounds,
    )

    // Store user registration data
    const registrationData: RegistrationData = {
      owner: this.ownerId,
      authenticationSalt: salts.authentication,
      encryptionSalt: salts.encryption,
      pbkdfRounds: this.pbkdfRounds,
      verifier: verifier.blob,
      verifierIv: verifier.iv,
    }

    try {
      const db = await this.db
      await new Promise((resolve, reject) => {
        const registrationRequest = db
          .transaction(['registration'], 'readwrite')
          .objectStore('registration')
          .add(registrationData)

        registrationRequest.onsuccess = () => {
          resolve()
        }
        registrationRequest.onerror = () => {
          reject(registrationRequest.error)
        }
      })
    } catch (error) {
      if (error.name === 'ConstraintError')
        throw new SecureVaultAlreadyRegisteredError()
      else throw error
    }

    return registrationData.owner
  }

  async isRegistered(): Promise<boolean> {
    return (await this.getInitializationData()) !== undefined
  }

  async createVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    rawBlob: ArrayBuffer,
    blobFormat: string,
    ownershipProof: string,
  ): Promise<VaultMetadata> {
    const registrationData = await this.verifyCredentials(key, password)

    // TODO: Extract owner string from ownership proof.
    const [owner, issuer] = ownershipProof.split(':')

    const { blob, iv } = await cryptoProvider.encryptVaultBlob(
      key,
      password,
      registrationData.encryptionSalt,
      registrationData.pbkdfRounds,
      rawBlob,
    )

    const db = await this.db

    return await new Promise((resolve, reject) => {
      const id = uuid()
      const now = new Date()
      const metadata: VaultMetadata = {
        id: String(id),
        version: 0,
        blobFormat,
        createdAt: now,
        updatedAt: now,
        owner,
        owners: [{ id: owner, issuer }],
      }
      const vault: Vault = {
        ...metadata,
        blob,
      }

      const request = db
        .transaction(['vaults'], 'readwrite')
        .objectStore('vaults')
        .add({ ...vault, iv })

      request.onerror = () => {
        reject(request.error)
      }

      request.onsuccess = () => {
        resolve(metadata)
      }
    })
  }

  async updateVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    id: string,
    version: number,
    rawBlob: ArrayBuffer,
    blobFormat: string,
  ): Promise<VaultMetadata> {
    const registrationData = await this.verifyCredentials(key, password)

    const db = await this.db

    const { blob, iv } = await cryptoProvider.encryptVaultBlob(
      key,
      password,
      registrationData.encryptionSalt,
      registrationData.pbkdfRounds,
      rawBlob,
    )

    // Only update the vault if decryption succeeds.
    const oldItem = await this.getVault(key, password, id)
    if (oldItem === undefined) throw new InvalidVaultError()

    return await new Promise((resolve, reject) => {
      const transaction = db.transaction(['vaults'], 'readwrite')
      const vaultStore = transaction.objectStore('vaults')

      transaction.onabort = () => {
        reject(transaction.error)
      }

      const getRequest = vaultStore.get(id)

      getRequest.onsuccess = () => {
        const oldItem = getRequest.result as StoredVault<unknown> | undefined

        if (oldItem === undefined) return reject(new InvalidVaultError())

        if (oldItem.version !== version)
          return reject(new VersionMismatchError())

        const newVault: StoredVault<unknown> = {
          ...oldItem,
          blob,
          iv,
          version: version + 1,
          blobFormat,
          updatedAt: new Date(),
        }

        vaultStore.put(newVault).onsuccess = () => resolve(newVault)
      }
    })
  }

  /**
   * Replaces a locally stored vault with the provided blob.
   * This is only useful when synchronizing with another secure vault service.
   * If that is not the case, instead use {@link updateVault}.
   *
   * @param key current registered key deriving key
   * @param password current registered password
   * @param vault vault to store
   * @param expectedVersion the currently stored vault will be atomically compared
   * with this version and this function will throw `VersionMismatchError` if
   * the version is no longer the same.
   * @param additionalMetadata Additional metadata to store with the vault.
   */
  async setVault<T>(
    key: ArrayBuffer,
    password: ArrayBuffer,
    vault: Vault,
    expectedVersion: number,
    additionalMetadata?: T,
  ): Promise<void> {
    const registrationData = await this.verifyCredentials(key, password)

    const db = await this.db

    const { blob, iv } = await cryptoProvider.encryptVaultBlob(
      key,
      password,
      registrationData.encryptionSalt,
      registrationData.pbkdfRounds,
      vault.blob,
    )

    const newVault: StoredVault<T> = {
      ...vault,
      additionalMetadata,
      blob,
      iv,
    }

    return await new Promise((resolve, reject) => {
      const transaction = db.transaction(['vaults'], 'readwrite')
      const vaultStore = transaction.objectStore('vaults')

      transaction.onabort = () => {
        reject(transaction.error)
      }

      const getRequest = vaultStore.get(vault.id)

      getRequest.onsuccess = () => {
        // Abort put() if existing item has changed concurrently with us.
        const oldItem = getRequest.result as StoredVault<unknown> | undefined
        if (oldItem !== undefined && oldItem.version !== expectedVersion)
          return reject(new VersionMismatchError())

        vaultStore.put(newVault).onsuccess = () => resolve()
      }
    })
  }

  async deleteVault(id: string): Promise<VaultMetadata> {
    if (!(await this.getInitializationData())) throw new NotRegisteredError()

    const db = await this.db

    return await new Promise((resolve, reject) => {
      const transaction = db.transaction(['vaults'], 'readwrite')
      const vaultStore = transaction.objectStore('vaults')

      transaction.onabort = () => {
        reject(transaction.error)
      }

      const getRequest = vaultStore.get(id)

      getRequest.onsuccess = () => {
        const oldItem = getRequest.result as StoredVault<unknown> | undefined
        if (!oldItem) return reject(new InvalidVaultError())

        vaultStore.delete(id).onsuccess = () => resolve()
      }
    })
  }

  async getVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    id: string,
  ): Promise<Vault | undefined> {
    const registrationData = await this.verifyCredentials(key, password)

    const db = await this.db

    const item: StoredVault<unknown> | undefined = await new Promise(
      (resolve, reject) => {
        const request = db
          .transaction(['vaults'], 'readonly')
          .objectStore('vaults')
          .get(id)

        request.onerror = () => {
          reject(request.error)
        }

        request.onsuccess = () => {
          resolve(request.result)
        }
      },
    )

    if (item === undefined) return undefined

    const { iv, ...vault } = item

    const decrypted = await cryptoProvider.decryptVaultBlob(
      key,
      password,
      registrationData.encryptionSalt,
      registrationData.pbkdfRounds,
      iv,
      vault.blob,
    )

    return { ...vault, blob: decrypted }
  }

  async listVaults(
    key: ArrayBuffer,
    password: ArrayBuffer,
  ): Promise<LocalVault<unknown>[]> {
    const registrationData = await this.verifyCredentials(key, password)

    const db = await this.db

    const items: StoredVault<unknown>[] = await new Promise(
      (resolve, reject) => {
        const request = db
          .transaction(['vaults'], 'readonly')
          .objectStore('vaults')
          .getAll()

        request.onerror = () => {
          reject(request.error)
        }

        request.onsuccess = () => {
          resolve(request.result)
        }
      },
    )

    return await Promise.all(
      items.map(async ({ iv, ...item }) => {
        const decrypted = await cryptoProvider.decryptVaultBlob(
          key,
          password,
          registrationData.encryptionSalt,
          registrationData.pbkdfRounds,
          iv,
          item.blob,
        )
        return { ...item, blob: decrypted }
      }),
    )
  }

  async listVaultsMetadataOnly(): Promise<VaultMetadata[]> {
    if (!(await this.getInitializationData())) throw new NotRegisteredError()

    const db = await this.db

    const items: StoredVault<unknown>[] = await new Promise(
      (resolve, reject) => {
        const request = db
          .transaction(['vaults'], 'readonly')
          .objectStore('vaults')
          .getAll()

        request.onerror = () => {
          reject(request.error)
        }

        request.onsuccess = () => {
          resolve(request.result)
        }
      },
    )

    return items.map(
      ({ id, version, createdAt, updatedAt, blobFormat, owner, owners }) => ({
        id,
        version,
        createdAt,
        updatedAt,
        blobFormat,
        owner,
        owners,
      }),
    )
  }

  async changeVaultPassword(
    key: ArrayBuffer,
    oldPassword: ArrayBuffer,
    newPassword: ArrayBuffer,
  ): Promise<void> {
    const registrationData = await this.verifyCredentials(key, oldPassword)

    const newVerifier = await this.computeRegistrationVerifier(
      key,
      newPassword,
      registrationData.encryptionSalt,
      registrationData.pbkdfRounds,
    )

    const newRegistrationData: RegistrationData = {
      ...registrationData,
      verifier: newVerifier.blob,
      verifierIv: newVerifier.iv,
    }

    const db = await this.db

    type DBVault = StoredVault<unknown>
    const sortVaults = (vaults: DBVault[]): DBVault[] =>
      vaults.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())

    // fetch all vaults to re-encrypt them
    const allVaults: DBVault[] = await new Promise((resolve, reject) => {
      const request = db
        .transaction(['vaults'], 'readonly')
        .objectStore('vaults')
        .getAll()

      request.onsuccess = () => resolve(request.result)

      request.onerror = () => reject(request.error)
    })
    sortVaults(allVaults)

    // re-encrypt all vaults
    const reencryptedVaults: DBVault[] = await Promise.all(
      allVaults.map(async (vault) => {
        const decrypted = await cryptoProvider.decryptVaultBlob(
          key,
          oldPassword,
          registrationData.encryptionSalt,
          registrationData.pbkdfRounds,
          vault.iv,
          vault.blob,
        )

        const reencrypted = await cryptoProvider.encryptVaultBlob(
          key,
          newPassword,
          newRegistrationData.encryptionSalt,
          registrationData.pbkdfRounds,
          decrypted,
        )

        return {
          ...vault,
          blob: reencrypted.blob,
          iv: reencrypted.iv,
        }
      }),
    )

    await new Promise((resolve, reject) => {
      // transaction that updates registration data and re-encrypts vaults
      const transaction = db.transaction(
        ['registration', 'vaults'],
        'readwrite',
      )

      transaction.oncomplete = () => {
        resolve()
      }

      transaction.onabort = () => {
        reject(transaction.error)
      }

      // update registration data
      transaction.objectStore('registration').put(newRegistrationData)

      // replace vaults with re-encrypted vaults
      const vaultStore = transaction.objectStore('vaults')
      vaultStore.getAll().onsuccess = (event) => {
        // compare all vaults currently in db to what we re-encrypted.
        // we have to take a chance that the data may have changed in
        // the mean time since re-encryption is asynchronous.
        type VaultsRequest = IDBRequest<DBVault[]>
        const vaults = (event.target as VaultsRequest).result
        sortVaults(vaults)

        if (
          vaults.length !== allVaults.length ||
          allVaults.find((item, index) => vaults[index].id !== item.id)
        ) {
          // a change has occurred to the database since we re-encrypted vaults.
          // let the caller decide whether or not to try again.
          throw new VersionMismatchError()
        }

        // clear db of old vaults and store the re-encrypted vaults
        vaultStore.clear().onsuccess = () => {
          reencryptedVaults.forEach((vault) => vaultStore.add(vault))
        }
      }
    })
  }

  async deregister(): Promise<void> {
    // Since all data for this service is local,
    // deregistration is equivalent to `reset`.
    await this._reset()
  }

  reset(): void {
    this._reset().catch(() => {
      /* best-effort */
    })
  }

  /**
   * Deletes all local secure vault service data.
   */
  private async _reset(): Promise<void> {
    const db = await this.db
    await new Promise((resolve, reject) => {
      const transaction = db.transaction(
        ['registration', 'vaults'],
        'readwrite',
      )

      transaction.objectStore('registration').clear()
      transaction.objectStore('vaults').clear()

      transaction.oncomplete = () => resolve()
      transaction.onabort = () => reject(transaction.error)
    })
  }

  /**
   * Returns the user's stored `RegistrationData` or `undefined` if not registered.
   */
  async getInitializationData(): Promise<RegistrationData | undefined> {
    const db = await this.db
    return await new Promise((resolve, reject) => {
      const registrationRequest = db
        .transaction(['registration'], 'readwrite')
        .objectStore('registration')
        .get(this.ownerId)

      registrationRequest.onsuccess = () => {
        resolve(registrationRequest.result)
      }
      registrationRequest.onerror = () => {
        reject(registrationRequest.error)
      }
    })
  }

  /**
   * Computes the registration verifier from the key deriving key and password
   * that the user will use for all vaults.
   */
  private async computeRegistrationVerifier(
    key: ArrayBuffer,
    password: ArrayBuffer,
    encryptionSalt: ArrayBuffer,
    pbkdfRounds: number,
  ): Promise<{ blob: ArrayBuffer; iv: ArrayBuffer }> {
    return await cryptoProvider.encryptVaultBlob(
      key,
      password,
      encryptionSalt,
      pbkdfRounds,
      new Uint8Array(JSON.parse('[78,69,86,69,82,71,79,78,78,65,71,73,86,69]')),
    )
  }

  /**
   * Verifies the provided key deriving key and password against the
   * key and password that were used when the user registered.
   * @param key key deriving key
   * @param password vault password
   * @throws NotRegisteredError if the user has not registered.
   * @throws NotAuthorizedError if credentials do not match
   */
  private async verifyCredentials(
    key: ArrayBuffer,
    password: ArrayBuffer,
  ): Promise<RegistrationData> {
    const registrationData = await this.getInitializationData()
    if (!registrationData) throw new NotRegisteredError()

    // throws NotAuthorizedError if credentials don't match
    const decryptedVerifier = await cryptoProvider.decryptVaultBlob(
      key,
      password,
      registrationData.encryptionSalt,
      registrationData.pbkdfRounds,
      registrationData.verifierIv,
      registrationData.verifier,
    )

    // probably an unreachable state, since decryption would fail
    if (
      JSON.stringify(Array.from(new Uint8Array(decryptedVerifier))) !==
      '[78,69,86,69,82,71,79,78,78,65,71,73,86,69]'
    ) {
      throw new NotAuthorizedError()
    }

    return registrationData
  }
}
