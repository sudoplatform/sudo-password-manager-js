import { KeyDerivingKeyStore } from '../types'

export class InMemoryKeyDerivingKeyStore implements KeyDerivingKeyStore {
  private key: ArrayBuffer | undefined

  async get(): Promise<ArrayBuffer | undefined> {
    if (!this.key) return

    const copy = new Uint8Array(this.key.byteLength)
    copy.set(new Uint8Array(this.key))
    return copy
  }

  async set(key: ArrayBuffer | undefined): Promise<void> {
    if (key) {
      const copy = new Uint8Array(key.byteLength)
      copy.set(new Uint8Array(key))
      this.key = copy
    } else {
      this.key = undefined
    }
  }
}
