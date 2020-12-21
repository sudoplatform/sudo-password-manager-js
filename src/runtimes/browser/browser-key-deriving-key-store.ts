import { KeyDerivingKeyStore } from '../../types'

/** A pair of (id, CryptoKey) */
interface StoredKey {
  id: string
  key: CryptoKey
}

/** The name of the IndexedDB database to access. */
const DB_NAME = 'com.sudoplatform.passwordmanager.keyderivingkey'

export class BrowserKeyDerivingKeyStore implements KeyDerivingKeyStore {
  private db: Promise<IDBDatabase>

  constructor() {
    this.db = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1)

      request.onsuccess = (_event) => {
        const db = request.result
        resolve(db)
      }

      request.onerror = (_event) => {
        reject(request.error)
      }

      request.onupgradeneeded = (event) => {
        if (event.oldVersion === 0 && event.newVersion === 1) {
          const db = request.result

          // Migrate DB tables from version 0 to version 1
          db.createObjectStore('keys', {
            keyPath: 'id',
            autoIncrement: false,
          })
        }
      }
    })
  }

  async get(): Promise<ArrayBuffer | undefined> {
    const db = await this.db

    const item: StoredKey | undefined = await new Promise((resolve, reject) => {
      const request = db
        .transaction(['keys'], 'readonly')
        .objectStore('keys')
        .get('key deriving key')

      request.onerror = () => {
        reject(request.error)
      }

      request.onsuccess = () => {
        resolve(request.result)
      }
    })

    if (!item) return undefined

    // TODO: Return actual CryptoKey directly to caller?
    return await crypto.subtle.exportKey('raw', item.key)
  }

  async set(key_: ArrayBuffer | undefined): Promise<void> {
    if (!key_) return await this._delete()

    const key = await crypto.subtle.importKey('raw', key_, 'AES-CBC', true, [
      'encrypt',
      'decrypt',
    ])

    const db = await this.db
    const item: StoredKey = { id: 'key deriving key', key }

    await new Promise((resolve, reject) => {
      const request = db
        .transaction(['keys'], 'readwrite')
        .objectStore('keys')
        .put(item)

      request.onerror = () => {
        reject(request.error)
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }

  async _delete(): Promise<void> {
    const db = await this.db

    await new Promise((resolve, reject) => {
      const request = db
        .transaction(['keys'], 'readwrite')
        .objectStore('keys')
        .delete('key deriving key')

      request.onerror = () => {
        reject(request.error)
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }
}
