import {
  NotAuthorizedError,
  NotRegisteredError,
  VersionMismatchError,
} from '@sudoplatform/sudo-common'
import { SudoSecureVaultClient } from '@sudoplatform/sudo-secure-vault'
import {
  VaultMetadata,
  Vault,
} from '@sudoplatform/sudo-secure-vault/lib/vault/vaultClient'
import {
  LocalSudoSecureVaultClient,
  LocalVault,
  SecureVaultAlreadyRegisteredError,
} from './local-secure-vault-service'
import { zerofill } from './utils/zerofill'

interface CachedVaultAdditionalMetadata {
  lastKnownRemoteVersion: number
}

/**
 * An implementation of `SudoSecureVaultClient` which maintains a local cache
 * for vault data that can be accessed and mutated while offline.
 *
 * Changes to the local cache will be periodically synchronized with the
 * remote secure vault service when it can be reached.
 *
 * Certain operations such as registering, deregistering, creating vaults,
 * deleting vaults, and changing password can only be performed when the
 * remote secure vault service can be reached.
 */
export class CachingSudoSecureVaultClient implements SudoSecureVaultClient {
  /** The current reconciliation task if one is in progress. */
  private reconciliationTask?: Promise<void>
  /** A list of (key, password) pairs pending reconciliation requests. */
  private pendingReconciliation: [ArrayBuffer, ArrayBuffer][] = []

  constructor(
    /**
     * The remote secure vault service.
     * This client is the source of truth across all devices,
     * but it may be slow to access or may not be reachable at all.
     */
    private readonly remoteService: SudoSecureVaultClient,

    /**
     * The local secure vault service which stores cached / offline vaults.
     */
    private readonly localService: LocalSudoSecureVaultClient,

    /**
     * A callback to be invoked when there is a merge conflict between the
     * remote and cached vaults. For instance, when a vault is updated on
     * Device A while it is offline and on Device B which is online.
     *
     * The callback should consider data from the local and remote vaults
     * and return a single merged vault blob + format to supercede them.
     */
    private readonly mergeVaults: (
      localVault: Vault,
      remoteVault: Vault,
    ) => { blob: ArrayBuffer; blobFormat: string },

    /**
     * Called when an error occurs during background reconciliation,
     * i.e. when the caching client is synchronizing state with the
     * remote service *after* a call to `listVaults` or `updateVault` returns.
     *
     * Typically this error indicates that the remote service could not be
     * reached, which is expected to occur during offline operation.
     */
    private readonly logBackgroundReconciliationError: (error: unknown) => void,
  ) {}

  async getVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    id: string,
  ): Promise<Vault | undefined> {
    try {
      const cachedVault = await this.localService.getVault(key, password, id)

      // Kick off a background attempt to refresh the cache.
      this.kickoffBackgroundReconciliation(key, password)

      return cachedVault
    } catch (error) {
      if (error instanceof NotRegisteredError) {
        // the user has never populated the cache on this device.
        // block until we have populated the cache initially.
        this.kickoffBackgroundReconciliation(key, password)
        await this.awaitReconciliation()
        return await this.localService.getVault(key, password, id)
      } else if (error instanceof NotAuthorizedError) {
        // either the password was incorrect or changed remotely.
        // block on reconciliation so we update the cache if the user provided
        // a more up to date password so we don't give them an error.
        this.kickoffBackgroundReconciliation(key, password)
        await this.awaitReconciliation()
        return await this.localService.getVault(key, password, id)
      } else {
        throw error
      }
    }
  }

  async updateVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    id: string,
    version: number,
    blob: ArrayBuffer,
    format: string,
  ): Promise<VaultMetadata> {
    const doUpdate = (): Promise<VaultMetadata> =>
      this.localService.updateVault(key, password, id, version, blob, format)

    try {
      // Update the cache first. This will bump its `version` but not `lastKnownRemoteVersion`.
      const updated = await doUpdate()

      // Kick off a background attempt to reconcile the cache with remote.
      this.kickoffBackgroundReconciliation(key, password)

      return updated
    } catch (error) {
      if (error instanceof NotRegisteredError) {
        // the user has never populated the cache on this device.
        // block until we have populated the cache initially.
        this.kickoffBackgroundReconciliation(key, password)
        await this.awaitReconciliation()
        return await doUpdate()
      } else if (error instanceof NotAuthorizedError) {
        // either the password was incorrect or changed remotely.
        // block on reconciliation so we update the cache if the user provided
        // a more up to date password so we don't give them an error.
        this.kickoffBackgroundReconciliation(key, password)
        await this.awaitReconciliation()
        return await doUpdate()
      } else {
        throw error
      }
    }
  }

  async listVaults(key: ArrayBuffer, password: ArrayBuffer): Promise<Vault[]> {
    try {
      const cachedVaults = await this.localService.listVaults(key, password)

      this.kickoffBackgroundReconciliation(key, password)

      return cachedVaults
    } catch (error) {
      if (error instanceof NotRegisteredError) {
        // the user has never populated the cache on this device.
        // block until we have populated the cache initially.
        this.kickoffBackgroundReconciliation(key, password)
        await this.awaitReconciliation()
        return await this.localService.listVaults(key, password)
      } else if (error instanceof NotAuthorizedError) {
        // either the password was incorrect or changed remotely.
        // block on reconciliation so we update the cache if the user provided
        // a more up to date password so we don't give them an error.
        this.kickoffBackgroundReconciliation(key, password)
        await this.awaitReconciliation()
        return await this.localService.listVaults(key, password)
      } else {
        throw error
      }
    }
  }

  async listVaultsMetadataOnly(): Promise<VaultMetadata[]> {
    const [remoteResult, cachedResult] = await Promise.allSettled([
      this.remoteService.listVaultsMetadataOnly(),
      this.localService.listVaultsMetadataOnly(),
    ])

    // If we have a cached list and a remote list, the merge them,
    // using the cached metadata if there are duplicates.
    // This is because the version number from the cached metadata
    // is what getVault() returns and updateVault() requires.
    //
    // If we have only a cached list or only a remote list, return it.
    if (cachedResult.status === 'fulfilled') {
      if (remoteResult.status === 'fulfilled') {
        return remoteResult.value.map((remoteItem) => {
          const localItem = cachedResult.value.find(
            (item) => item.id === remoteItem.id,
          )
          return localItem ?? remoteItem
        })
      } else {
        return cachedResult.value
      }
    } else {
      if (remoteResult.status === 'fulfilled') {
        return remoteResult.value
      } else {
        throw remoteResult.reason
      }
    }
  }

  private kickoffBackgroundReconciliation(
    key_: ArrayBuffer,
    password_: ArrayBuffer,
  ): void {
    // Copy key and password to use beyond vault client method invocation.
    const key = new ArrayBuffer(key_.byteLength)
    new Uint8Array(key).set(new Uint8Array(key_))
    const password = new ArrayBuffer(password_.byteLength)
    new Uint8Array(password).set(new Uint8Array(password_))

    // If there is an in-progress reconciliation, simply add the credentials
    // to a queue of credentials waiting to be used in reconciliation.
    //
    // When the in-progress task finishes, it will perform reconciliation
    // using credentials from the queue until it empties.
    // This prevents simultaneous calls to _reconcile() which can race.
    //
    // It also means that awaitReconciliation() waits for the queue to empty,
    // rather than only awaiting the first or latest reconciliation and leaking
    // the remaining Promises.
    //
    // There is no point in enqueuing multiple copies of the same credentials.
    //
    // Lastly, this throttles reconciliation by only allowing one pending
    // task per unique key/password.
    //
    // In normal operation, this queue should be empty or have a single item,
    // because it is unlikely that the user will enter many passwords.
    if (this.reconciliationTask) {
      this.pendingReconciliation = this.pendingReconciliation.filter(
        ([keyB, passwordB]) =>
          key.toString() !== keyB.toString() &&
          password.toString() !== passwordB.toString(),
      )
      this.pendingReconciliation.push([key, password])
    } else {
      // Store this promise so we can await it to control timing.
      this.reconciliationTask = (async () => {
        let [currentKey, currentPassword] = [key, password]

        while (true) {
          try {
            await this._reconcile(currentKey, currentPassword)
          } catch (error) {
            this.logBackgroundReconciliationError(error)
          } finally {
            zerofill(currentKey)
            zerofill(currentPassword)

            const pendingRequest = this.pendingReconciliation.shift()
            if (pendingRequest) {
              ;[currentKey, currentPassword] = pendingRequest
            } else {
              this.reconciliationTask = undefined
              break
            }
          }
        }
      })()
    }
  }

  /** Awaits reconciliation if it is currently in progress. */
  async awaitReconciliation(): Promise<void> {
    await this.reconciliationTask
  }

  private async _reconcile(
    key: ArrayBuffer,
    password: ArrayBuffer,
  ): Promise<void> {
    // Attempt to fetch remote vaults in case we've gone online.
    const [remoteResult] = await Promise.allSettled([
      this.remoteService.listVaults(key, password),
    ])

    let remoteVaults: Vault[]
    let cachedVaults: LocalVault<CachedVaultAdditionalMetadata>[]

    // Handle case where remote password has changed.
    if (remoteResult.status === 'rejected') {
      if (remoteResult.reason instanceof NotAuthorizedError) {
        await this.registerLocalClientIfNeeded(key, password)
        const [cachedResult] = await Promise.allSettled([
          this.localService.listVaults(key, password),
        ])

        if (cachedResult.status === 'fulfilled') {
          // The caller provided a password that was previously valid.
          // Flag the local service as requiring a new password so that
          // the incorrect password error is raised to callers.
          await this.localService.changeVaultPassword(
            key,
            password,
            new Uint8Array([0]),
          )
          return
        } else if (cachedResult.reason instanceof NotAuthorizedError) {
          // The caller provided a password that is valid nowhere.
          // Suppress this error; the caller will see it regardless.
          return
        } else {
          throw remoteResult.reason
        }
      } else {
        throw remoteResult.reason
      }
    }

    await this.registerLocalClientIfNeeded(key, password)
    const [cachedResult] = await Promise.allSettled([
      this.localService.listVaults(key, password),
    ])

    if (cachedResult.status === 'rejected') {
      if (cachedResult.reason instanceof NotAuthorizedError) {
        if (remoteResult.status === 'fulfilled') {
          // The remote password must have changed without us knowing about it.
          // Forcibly change the local password to the remote password.
          // This has to clear cached data because we don't know the old password.
          await this.localService.deregister()
          await this.localService.register(key, password)
          remoteVaults = remoteResult.value
          cachedVaults = []
        } else {
          throw cachedResult.reason
        }
      } else {
        throw cachedResult.reason
      }
    } else {
      remoteVaults = remoteResult.value
      cachedVaults = cachedResult.value as LocalVault<
        CachedVaultAdditionalMetadata
      >[]
    }

    const vaultIds = new Set([
      ...remoteVaults.map((vault) => vault.id),
      ...cachedVaults.map((vault) => vault.id),
    ])

    await Promise.all(
      Array.from(vaultIds).map(async (vaultId) => {
        const remoteVault = remoteVaults.find((vault) => vault.id === vaultId)
        const cachedVault = cachedVaults.find((vault) => vault.id === vaultId)

        if (!remoteVault) {
          // If the remote vault is gone, delete the cached vault.
          // This is valid because we disallow creating vaults while offline.
          await this.localService.deleteVault(vaultId)
        } else if (!cachedVault) {
          // If the remote vault is new, store it in the cache.
          // If this throws VersionMismatchError then two calls to _reconcile()
          // occurred at the same time. That would be a bug.
          await this.localService.setVault(key, password, remoteVault, 0, {
            lastKnownRemoteVersion: remoteVault.version,
          } as CachedVaultAdditionalMetadata)
        } else {
          const cachedVaultLastKnownRemoteVersion =
            cachedVault.additionalMetadata?.lastKnownRemoteVersion
          if (cachedVaultLastKnownRemoteVersion === undefined)
            throw new Error('Programmer error - remote version should be in db')

          try {
            // If both vaults exist, perform conflict resolution if necessary:
            if (remoteVault.version > cachedVaultLastKnownRemoteVersion) {
              // The remote vault has changed since we cached it.
              if (cachedVault.version > cachedVaultLastKnownRemoteVersion) {
                // Our local vault has changed while offline.
                // Merge the cached vault with the remote vault and save.
                const mergedVault = this.mergeVaults(cachedVault, remoteVault)

                const updated = await this.remoteService.updateVault(
                  key,
                  password,
                  vaultId,
                  remoteVault.version,
                  mergedVault.blob,
                  mergedVault.blobFormat,
                )
                await this.localService.setVault(
                  key,
                  password,
                  {
                    ...updated,
                    ...mergedVault,
                  },
                  cachedVault.version,
                  {
                    lastKnownRemoteVersion: updated.version,
                  } as CachedVaultAdditionalMetadata,
                )
              } else {
                // Our local vault has not changed. Download the remote vault.
                await this.localService.setVault(
                  key,
                  password,
                  remoteVault,
                  cachedVault.version,
                  {
                    lastKnownRemoteVersion: remoteVault.version,
                  } as CachedVaultAdditionalMetadata,
                )
              }
            } else {
              // The remote vault has not changed since we cached it.
              if (cachedVault.version > cachedVaultLastKnownRemoteVersion) {
                // Our local vault has changed while offline. Upload it.
                const updated = await this.remoteService.updateVault(
                  key,
                  password,
                  vaultId,
                  remoteVault.version,
                  cachedVault.blob,
                  cachedVault.blobFormat,
                )
                await this.localService.setVault(
                  key,
                  password,
                  { ...cachedVault, ...updated, blob: cachedVault.blob },
                  cachedVault.version,
                  {
                    lastKnownRemoteVersion: updated.version,
                  } as CachedVaultAdditionalMetadata,
                )
              } else {
                // Neither vault has changed since the last reconciliation. Done.
              }
            }
          } catch (error) {
            if (error instanceof VersionMismatchError) {
              // Either the remote or cached vault changed during reconciliation.
              // The update will be re-applied and retried next reconciliation.
            } else throw error
          }
        }
      }),
    )
  }

  async createVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    blob: ArrayBuffer,
    blobFormat: string,
    ownershipProof: string,
  ): Promise<VaultMetadata> {
    // Creating a vault is a remote-first operation that will
    // only succeed if the remote vault can be created.
    const created = await this.remoteService.createVault(
      key,
      password,
      blob,
      blobFormat,
      ownershipProof,
    )

    // Update the cache with the created vault.
    await this.registerLocalClientIfNeeded(key, password)
    await this.localService.setVault(
      key,
      password,
      {
        ...created,
        blob,
      },
      0,
      {
        lastKnownRemoteVersion: created.version,
      } as CachedVaultAdditionalMetadata,
    )

    return created
  }

  async deleteVault(id: string): Promise<VaultMetadata | undefined> {
    // Deleting a vault is a remote-first operation that will
    // only succeed if the remote vault can be deleted.
    const deleted = await this.remoteService.deleteVault(id)
    try {
      await this.localService.deleteVault(id)
    } catch (error) {
      if (error instanceof NotRegisteredError) {
        // If the cache isn't set up, don't worry about deleting vaults.
      } else throw error
    }
    return deleted
  }

  async register(key: ArrayBuffer, password: ArrayBuffer): Promise<string> {
    // Registration is a remote-first operation.
    const username = await this.remoteService.register(key, password)

    // If local registration fails, it will be registered on-demand.
    try {
      await this.localService.register(key, password)
    } catch (error) {
      if (error instanceof SecureVaultAlreadyRegisteredError) {
        // Reconciliation will fix this if necessary.
      } else throw error
    }

    return username
  }

  async getInitializationData(): ReturnType<
    SudoSecureVaultClient['getInitializationData']
  > {
    // Only the remote initialization data is stable and has meaning.
    return await this.remoteService.getInitializationData()
  }

  async isRegistered(): Promise<boolean> {
    try {
      // Registration is a remote-only operation.
      return await this.remoteService.isRegistered()
    } catch (error) {
      // TODO: Catch only SVS offline error?
      // However, if we're offline, make our best guess.
      return await this.localService.isRegistered()
    }
  }

  private async registerLocalClientIfNeeded(
    key: ArrayBuffer,
    password: ArrayBuffer,
  ): Promise<void> {
    if (!(await this.localService.isRegistered())) {
      await this.localService.register(key, password)
    }
  }

  async changeVaultPassword(
    key: ArrayBuffer,
    oldPassword: ArrayBuffer,
    newPassword: ArrayBuffer,
  ): Promise<void> {
    // Changing the vault password is a remote-first operation that will
    // only succeed if the remote vault password can be changed.
    await this.remoteService.changeVaultPassword(key, oldPassword, newPassword)
    try {
      await this.localService.changeVaultPassword(key, oldPassword, newPassword)
    } catch (error) {
      // Even if the local password failed to change,
      // the reconciliation process will fix it later.
    }
  }

  reset(): void {
    // Reset both services. Reset remote service even if cache reset fails.
    try {
      this.localService.reset()
    } finally {
      this.remoteService.reset()
    }
  }

  async deregister(): Promise<void> {
    await Promise.all([
      this.remoteService.deregister(),
      this.localService.deregister().catch(() => {
        // Even if we failed to deregister the cache client,
        // the reconciliation process will fix it later.
      }),
    ])
  }
}
