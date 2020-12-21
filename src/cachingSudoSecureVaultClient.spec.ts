import {
  SudoSecureVaultClient,
  Vault as SecureVault,
} from '@sudoplatform/sudo-secure-vault/lib/vault/vaultClient'
import { CachingSudoSecureVaultClient } from './cachingSudoSecureVaultClient'
import { LocalSudoSecureVaultClient } from './local-secure-vault-service'
import { InvalidVaultError } from '@sudoplatform/sudo-secure-vault'
import {
  NotAuthorizedError,
  NotRegisteredError,
  VersionMismatchError,
} from '@sudoplatform/sudo-common'

require('fake-indexeddb/auto')
// eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-unsafe-assignment
const FDBFactory = require('fake-indexeddb/lib/FDBFactory')
afterEach(() => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
  indexedDB = new FDBFactory()
})

/** Thrown during unit tests to mock the remote service being unreaachable. */
class OfflineError extends Error {}

const getClient = (): {
  client: CachingSudoSecureVaultClient
  remoteClient: SudoSecureVaultClient
} => {
  // we use a local client with an isolated database as a stand-in for the remote client
  const remoteClient = new LocalSudoSecureVaultClient({
    databaseName: 'remote-client',
    pbkdfRounds: 5000,
  })

  // for our testing purposes the merge function will take two vault blobs,
  // decode the blobs as text, concatenate the text, and re-encode.
  const mergeFunction = (
    a: SecureVault,
    b: SecureVault,
  ): { blob: ArrayBuffer; blobFormat: string } => ({
    blob: new TextEncoder().encode(
      new TextDecoder().decode(a.blob) + new TextDecoder().decode(b.blob),
    ),
    blobFormat: a.blobFormat,
  })

  // called to handle errors during background reconciliation caused by tests
  const logBackgroundErrorFunction = (error: unknown): void => {
    // OfflineErrors are expected when we test offline operation
    if (error instanceof OfflineError) return

    // any other errors are unexpected and should cause a test failure
    fail({
      message: 'Unexpected error during background reconciliation.',
      error,
      errorConstructor: (error as any).constructor,
    })
  }

  const client = new CachingSudoSecureVaultClient(
    remoteClient,
    new LocalSudoSecureVaultClient({
      databaseName: 'cache-client',
      pbkdfRounds: 5000,
    }),
    mergeFunction,
    logBackgroundErrorFunction,
  )

  return { client, remoteClient }
}

/** A template string tag function that returns the string encoded to utf-8. */
const b = (strings: TemplateStringsArray, ...exps: unknown[]): ArrayBuffer =>
  new TextEncoder().encode(
    strings[0] + exps.map((e, i) => `${e}${strings[i + 1]}`).join(''),
  )

/** Key deriving key to use in tests. */
const kdk = new Uint8Array([42])
/** Vault password to use in tests. */
const password = new Uint8Array([1, 2, 3, 4, 5])

describe('#awaitReconciliation', () => {
  it('awaits latest reconciliation request', async () => {
    const { client, remoteClient } = getClient()

    // Create an initial vault from another client.
    await remoteClient.register(kdk, password)
    await remoteClient.createVault(kdk, password, b`Hello`, '', '')

    // Populate the local cache initially.
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(1)

    // Create a new vault from another client.
    await remoteClient.createVault(kdk, password, b`Hello2`, '', '')

    // Simulate the remote service is now unreachable from the local client.
    // Use the wrong password with the caching client to retrieve vaults.
    const originalRemoteListVaults = remoteClient.listVaults
    remoteClient.listVaults = jest.fn().mockRejectedValue(new OfflineError())

    // List vaults from the cached client. Expect the old cached list.
    // This will also kick off a reconciliation that will fail.
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(1)

    // Restore connectivity then list vaults again.
    // Expect the old cached list, but kick off reconciliation that will succeed.
    remoteClient.listVaults = originalRemoteListVaults
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(1)

    // Await reconciliation. If we are correctly awaiting the latest request,
    // then a subsequent call to list will return the latest remote values.
    await client.awaitReconciliation()
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(2)
  })

  it('changes password for cache when remote password changes', async () => {
    const { client, remoteClient } = getClient()

    // Create an initial vault from another client.
    await remoteClient.register(kdk, password)
    await remoteClient.createVault(kdk, password, b`Hello`, '', '')

    // Use the caching client to retrieve and cache remote vaults.
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(1)

    // Change the remote vault password from another client.
    const newPassword = b`NewPassword`
    await remoteClient.changeVaultPassword(kdk, password, newPassword)

    // Perform another operation on the local client.
    // It will either fail due to incorrect password (if reconciliation already occurred),
    // or it will succeed with the cached value but kick off reconciliation.
    await client
      .listVaults(kdk, password)
      .then((list) => expect(list).toHaveLength(1))
      .catch((error) => expect(error).toBeInstanceOf(NotAuthorizedError))

    // Reconciliation will either be done or in progress at this point.
    // In real code the user could just keep trying their operation and it will
    // eventually succeed (once reconciliation has completed), but in a unit test
    // we want to explicitly wait until reconciliation is complete.
    await client.awaitReconciliation()

    // Verify that using the old password from the caching client now fails.
    await expect(client.listVaults(kdk, password)).rejects.toThrowError(
      NotAuthorizedError,
    )

    // Verify that using the new password from the caching client now succeeds.
    await expect(client.listVaults(kdk, newPassword)).resolves.toHaveLength(1)
    await client.awaitReconciliation() // await dangling async task
  })
})

describe('#getVault', () => {
  it('blocks if cache is not yet populated', async () => {
    const { client, remoteClient } = getClient()

    // Create an initial vault from another client.
    await remoteClient.register(kdk, password)
    const created = await remoteClient.createVault(kdk, password, b`A`, '', '')

    // Get vault by ID from caching client.
    // Since the cache is not yet populated, getVault will block on remote fetch.
    await expect(client.getVault(kdk, password, created.id)).resolves.toEqual(
      expect.objectContaining(created),
    )
  })

  it('returns cached local vault if present', async () => {
    const { client, remoteClient } = getClient()

    // Create an initial vault from another client.
    await remoteClient.register(kdk, password)
    const created = await remoteClient.createVault(kdk, password, b`A`, '', '')

    // Populate the cache with all vaults initially.
    await client.listVaults(kdk, password)

    // Simulate offline interaction - the remote service cannot be reached.
    remoteClient.listVaults = jest.fn().mockRejectedValue(new OfflineError())

    // Get vault by ID from caching client.
    await expect(client.getVault(kdk, password, created.id)).resolves.toEqual(
      expect.objectContaining(created),
    )
  })

  it('caches vault after reconciliation if not present', async () => {
    const { client, remoteClient } = getClient()

    // Create an initial vault from another client.
    await remoteClient.register(kdk, password)
    await remoteClient.createVault(kdk, password, b`A`, '', '')

    // Populate the cache with all vaults initially.
    await client.listVaults(kdk, password)

    // Create another vault on the remote service.
    const created2 = await remoteClient.createVault(kdk, password, b`B`, '', '')

    // Get the second vault from the caching client.
    // It will not be in the cache, so it will return undefined.
    // However it will kick off reconciliation and then add it to the cache.
    await expect(client.getVault(kdk, password, created2.id)) //
      .resolves.toBeUndefined()

    // After reconciliation completes, we can now retrieve the second vault.
    await client.awaitReconciliation()

    remoteClient.listVaults = jest.fn().mockRejectedValue(new OfflineError())

    await expect(client.getVault(kdk, password, created2.id)) //
      .resolves.toEqual(expect.objectContaining(created2))
  })

  it('throws if not registered', async () => {
    const client = new CachingSudoSecureVaultClient(
      new LocalSudoSecureVaultClient({
        databaseName: 'remote-client',
        pbkdfRounds: 5000,
      }),
      new LocalSudoSecureVaultClient({
        databaseName: 'cache-client',
        pbkdfRounds: 5000,
      }),
      (a, _b) => a,
      () => void 0 /* ignore not registered error */,
    )
    await expect(client.getVault(kdk, password, '')).rejects.toThrowError(
      NotRegisteredError,
    )
  })

  it('throws if password is incorrect', async () => {
    const { client } = getClient()

    await client.register(kdk, password)

    await expect(
      client.getVault(kdk, b`WrongPassword`, ''),
    ).rejects.toThrowError(NotAuthorizedError)
  })
})

describe('#listVaults', () => {
  it('caches remote vault list', async () => {
    const { client, remoteClient } = getClient()

    // Create an initial vault from another client.
    await remoteClient.register(kdk, password)
    await remoteClient.createVault(kdk, password, b`Hello`, '', '')

    // Use the caching client to retrieve and cache remote vaults.
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(1)

    // Simulate offline interaction - the remote service cannot be reached.
    remoteClient.listVaults = jest.fn().mockRejectedValue(new OfflineError())

    // The caching client should continue to return cached vaults.
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(1)
    await client.awaitReconciliation() // await dangling async task
  })

  it('returns new remote vaults after reconciliation', async () => {
    const { client, remoteClient } = getClient()

    // Create an initial vault from another client.
    await remoteClient.register(kdk, password)
    await remoteClient.createVault(kdk, password, b`Hello`, '', '')

    // Use the caching client to retrieve and cache remote vaults.
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(1)

    // Create another vault remotely.
    await remoteClient.createVault(kdk, password, b`Hello2`, '', '')

    // Initially the caching client will return only the cached data.
    // However, it will kick off reconciliation to download remote vaults.
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(1)

    // Normal user code would just see the new vault the next time the
    // user calls listVaults() after reconciliation has completed.
    // However in the unit test, we explicitly wait until that occurs.
    await client.awaitReconciliation()

    // After reconciliation we now see both remote vaults.
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(2)
    await client.awaitReconciliation() // await dangling async task
  })
})

describe('#listVaultsMetadataOnly', () => {
  it('merges metadata list when online', async () => {
    const { client, remoteClient } = getClient()

    // create a vault on the remote service
    await remoteClient.register(kdk, password)
    const vault1 = await remoteClient.createVault(kdk, password, b`A`, '', '')

    // populate the cache initially
    await client.listVaults(kdk, password)

    // 1. create a vault on the remote service that isn't in the cache.
    const vault2 = await remoteClient.createVault(kdk, password, b`B`, '', '')

    // simulate going offline
    const originalRemoteListVaults = remoteClient.listVaults
    const originalRemoteUpdateVault = remoteClient.updateVault
    remoteClient.listVaults = remoteClient.updateVault = jest
      .fn()
      .mockRejectedValue(new OfflineError())

    // 2. make an update to the vault from the caching client.
    //    it will bump the local cached version, but fail to upload remotely.
    await client.updateVault(kdk, password, vault1.id, vault1.version, b`C`, '')
    await client.awaitReconciliation()

    // go back online
    remoteClient.listVaults = originalRemoteListVaults
    remoteClient.updateVault = originalRemoteUpdateVault

    // now there are 3 distinct vaults:
    // 1. the `A` vault which is the remote version of vault1 (not in cache)
    // 2. the `B` vault which is the remote version of vault2 (not in cache)
    // 3. the `C` vault which is the cached, updated version of vault1

    // we expect listVaultsMetadataOnly to return the latest of each, so B and C.
    const metadataList = await client.listVaultsMetadataOnly()
    expect(metadataList).toHaveLength(2)
    expect(metadataList).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: vault1.id, version: vault1.version + 1 }),
        expect.objectContaining({ id: vault2.id, version: vault2.version }),
      ]),
    )
  })

  it('returns remote list when cache is empty', async () => {
    const { client, remoteClient } = getClient()

    // register on the remote service
    await remoteClient.register(kdk, password)

    // sanity check that the initial list of metadata is empty
    await expect(client.listVaultsMetadataOnly()).resolves.toHaveLength(0)

    // create a vault on the remote service
    await remoteClient.createVault(kdk, password, b`Hello`, '', '')

    // list metadata from the caching client without first populating the cache
    // it should return the remote list now with 1 item
    await expect(client.listVaultsMetadataOnly()).resolves.toHaveLength(1)
  })

  it('returns list of cached vaults when offline', async () => {
    const { client, remoteClient } = getClient()

    // create a vault on the remote service
    await remoteClient.register(kdk, password)
    await remoteClient.createVault(kdk, password, b`Hello`, '', '')

    // populate the local cache initially
    await client.listVaults(kdk, password)

    // create a vault on the remote service without updating the cache
    await remoteClient.createVault(kdk, password, b`Hello2`, '', '')

    // simulate offline operation - the remote service cannot be reached
    remoteClient.listVaultsMetadataOnly = remoteClient.listVaults = jest
      .fn()
      .mockRejectedValue(new OfflineError())

    // verify that the caching client lists only the 1 vault it has cached
    await expect(client.listVaults(kdk, password)).resolves.toHaveLength(1)
  })
})

describe('#updateVault', () => {
  it('updates locally then remotely after reconciliation', async () => {
    const { client, remoteClient } = getClient()

    // create a vault through the caching client
    // which will store the vault in the cache so it can be updated.
    await client.register(kdk, password)
    const vault = await client.createVault(kdk, password, b`A`, '', '')

    // update the vault through the caching client
    await client.updateVault(kdk, password, vault.id, vault.version, b`B`, '')

    // we should immediately see this new version in the cache.
    const cacheUpdated = await client.getVault(kdk, password, vault.id)
    expect(cacheUpdated?.blob).toEqual(b`B`)
    expect(cacheUpdated?.version).toEqual(vault.version + 1)

    // after reconciliation this update should also be made on the remote service.
    await client.awaitReconciliation()
    const remoteUpdated = await remoteClient.getVault(kdk, password, vault.id)
    expect(remoteUpdated?.blob).toEqual(b`B`)
    expect(remoteUpdated?.version).toEqual(vault.version + 1)
  })

  it('batches updates while offline then reconciles', async () => {
    const { client, remoteClient } = getClient()

    // create a vault through the caching client
    // which will store the vault in the cache so it can be updated.
    await client.register(kdk, password)
    const created = await client.createVault(kdk, password, b`A`, '', '')

    // simulate offline operation - the remote service cannot be reached.
    const originalRemoteListVaults = remoteClient.listVaults
    const originalRemoteUpdateVault = remoteClient.updateVault
    remoteClient.listVaults = remoteClient.updateVault = jest
      .fn()
      .mockRejectedValue(new OfflineError())

    // make an update to the vault while offline
    let updated = await client.updateVault(
      kdk,
      password,
      created.id,
      created.version,
      b`B`,
      '',
    )
    expect(updated.version).toEqual(created.version + 1)

    // make another update to the vault while offline
    updated = await client.updateVault(
      kdk,
      password,
      created.id,
      updated.version,
      b`C`,
      '',
    )
    expect(updated.version).toEqual(created.version + 2)

    // verify that updates were applied to cache
    const fetched = await client.getVault(kdk, password, created.id)
    expect(fetched?.blob).toEqual(b`C`)
    expect(fetched?.version).toEqual(updated.version)

    // simulate reconnecting to the remote service.
    await client.awaitReconciliation()
    remoteClient.listVaults = originalRemoteListVaults
    remoteClient.updateVault = originalRemoteUpdateVault

    // perform an action that causes reconciliation
    await client.getVault(kdk, password, created.id)
    await client.awaitReconciliation()

    // our updates should now be visible on the remote service.
    const remoteUpdated = await remoteClient.getVault(kdk, password, created.id)
    expect(remoteUpdated?.blob).toEqual(b`C`)
    expect(remoteUpdated?.version).toEqual(created.version + 1)

    // furthermore our cached version number should now match remote.
    const fetchedAfter = await client.getVault(kdk, password, created.id)
    expect(fetchedAfter?.blob).toEqual(b`C`)
    expect(fetchedAfter?.version).toEqual(created.version + 1)
  })

  it('merges vaults if cached and remote have both changed', async () => {
    const { client, remoteClient } = getClient()

    // create a vault through the caching client
    // which will store the vault in the cache so it can be updated.
    await client.register(kdk, password)
    const created = await client.createVault(kdk, password, b`A`, '', '')

    // create an update on the remote service that isn't in the cache
    const remoteUpdated = await remoteClient.updateVault(
      kdk,
      password,
      created.id,
      created.version,
      b`B`,
      '',
    )

    // simulate offline operation - the remote service cannot be reached.
    const originalRemoteListVaults = remoteClient.listVaults
    const originalRemoteUpdateVault = remoteClient.updateVault
    remoteClient.listVaults = remoteClient.updateVault = jest
      .fn()
      .mockRejectedValue(new OfflineError())

    // create an update in the cache while offline
    await client.updateVault(
      kdk,
      password,
      created.id,
      created.version,
      b`C`,
      '',
    )

    // simulate reconnecting to the remote service.
    await client.awaitReconciliation()
    remoteClient.listVaults = originalRemoteListVaults
    remoteClient.updateVault = originalRemoteUpdateVault

    // perform an action that causes reconciliation.
    // until reconciliation completes we will continue to read the cached value.
    let fetched = await client.getVault(kdk, password, created.id)
    expect(fetched?.blob).toEqual(b`C`)
    expect(fetched?.version).toEqual(created.version + 1)

    // after reconciliation the conflicting vaults should be merged.
    // note that the merge algorithm for the unit tests concatenates the blobs.
    await client.awaitReconciliation()

    fetched = await client.getVault(kdk, password, created.id)
    expect(fetched?.blob).toEqual(b`CB`)
    expect(fetched?.version).toEqual(remoteUpdated.version + 1)

    // this merged vault should also have been uploaded to the remote service.
    const remoteLatest = await remoteClient.getVault(kdk, password, created.id)
    expect(remoteLatest?.blob).toEqual(b`CB`)
    expect(remoteLatest?.version).toEqual(remoteUpdated.version + 1)
  })

  it('throws incorrect password error', async () => {
    const { client } = getClient()
    await client.register(kdk, password)
    await expect(
      client.updateVault(kdk, b`WrongPassword`, '', 0, b``, ''),
    ).rejects.toThrowError(NotAuthorizedError)
  })

  it('throws vault not found error', async () => {
    const { client, remoteClient } = getClient()
    await remoteClient.register(kdk, password)
    await expect(
      client.updateVault(kdk, password, 'WrongId', 0, b``, ''),
    ).rejects.toThrowError(InvalidVaultError)
  })

  it('throws version mismatch error', async () => {
    const { client, remoteClient } = getClient()

    await remoteClient.register(kdk, password)
    const created = await remoteClient.createVault(kdk, password, b``, '', '')

    await expect(
      client.updateVault(
        kdk,
        password,
        created.id,
        created.version - 1,
        b``,
        '',
      ),
    ).rejects.toThrowError(VersionMismatchError)
  })
})

describe('#createVault', () => {
  it('creates remote vault and caches it', async () => {
    const { client, remoteClient } = getClient()

    await client.register(kdk, password)
    const created = await client.createVault(kdk, password, b`A`, '', '')

    // simulate offline interaction - remote service cannot be reached
    remoteClient.listVaults = remoteClient.getVault = jest
      .fn()
      .mockRejectedValue(new OfflineError())

    // verify that created vault is in cache and can still be retrieved.
    await expect(client.getVault(kdk, password, created.id)).resolves.toEqual(
      expect.objectContaining(created),
    )
  })

  it('fails when offline', async () => {
    const { client, remoteClient } = getClient()
    await client.register(kdk, password)

    remoteClient.createVault = jest.fn().mockRejectedValue(new OfflineError())

    await expect(
      client.createVault(kdk, password, b``, '', ''),
    ).rejects.toThrowError(OfflineError)
  })

  it('throws incorrect password error', async () => {
    const { client, remoteClient } = getClient()
    await remoteClient.register(kdk, password)

    // verify that using incorrect password fails
    await expect(
      client.createVault(kdk, b`WrongPassword`, b`A`, '', ''),
    ).rejects.toThrowError(NotAuthorizedError)

    // verify that using correct password still succeeds
    await expect(
      client.createVault(kdk, password, b`A`, '', ''),
    ).resolves.toBeDefined()
  })
})

describe('#deleteVault', () => {
  it('deletes remote vault and removes from cache', async () => {
    const { client, remoteClient } = getClient()
    await client.register(kdk, password)

    // create vault using caching client to cache vault
    const created = await client.createVault(kdk, password, b`A`, '', '')

    await client.deleteVault(created.id)

    // should be deleted in cache and remotely
    await expect(client.listVaultsMetadataOnly()).resolves.toHaveLength(0)
    await expect(remoteClient.listVaultsMetadataOnly()).resolves.toHaveLength(0)
  })

  it('fails when offline', async () => {
    const { client, remoteClient } = getClient()
    await client.register(kdk, password)

    remoteClient.deleteVault = jest.fn().mockRejectedValue(new OfflineError())

    await expect(client.deleteVault('')).rejects.toThrowError(OfflineError)
  })
})

describe('#register', () => {
  it('registers', async () => {
    const { client, remoteClient } = getClient()
    await expect(client.register(kdk, password)).resolves.toBeTruthy()
    await expect(remoteClient.isRegistered()).resolves.toBe(true)
    await expect(client.isRegistered()).resolves.toBe(true)
  })

  it('fails when offline', async () => {
    const { client, remoteClient } = getClient()
    remoteClient.register = jest.fn().mockRejectedValue(new OfflineError())
    await expect(client.register(kdk, password)).rejects.toThrowError(
      OfflineError,
    )
  })
})

describe('#getInitializationData', () => {
  it('gets initialization data', async () => {
    const { client, remoteClient } = getClient()

    await expect(client.getInitializationData()).resolves.toBeUndefined()

    await client.register(kdk, password)

    const initializationData = await client.getInitializationData()
    expect(initializationData).toBeDefined()
    await expect(remoteClient.getInitializationData()).resolves.toEqual(
      initializationData,
    )
  })

  it('fails when offline', async () => {
    const { client, remoteClient } = getClient()

    await client.register(kdk, password)

    remoteClient.getInitializationData = jest
      .fn()
      .mockRejectedValue(new OfflineError())

    await expect(client.getInitializationData()).rejects.toThrowError(
      OfflineError,
    )
  })
})

describe('#isRegistered', () => {
  it('checks if registered with remote service', async () => {
    const { client } = getClient()
    await expect(client.isRegistered()).resolves.toBe(false)
    await client.register(kdk, password)
    await expect(client.isRegistered()).resolves.toBe(true)
  })

  it('can check registration status even if offline', async () => {
    const { client, remoteClient } = getClient()

    // simulate offline interaction - remote service cannot be reached
    const originalRemoteIsRegistered = remoteClient.isRegistered
    remoteClient.isRegistered = jest.fn().mockRejectedValue(new OfflineError())

    // verify that isRegistered returns false
    await expect(client.isRegistered()).resolves.toBe(false)

    // simulate reconnecting to service and register
    remoteClient.isRegistered = originalRemoteIsRegistered
    await client.register(kdk, password)

    // simulate offline interaction - remote service cannot be reached
    remoteClient.isRegistered = jest.fn().mockRejectedValue(new OfflineError())

    // verify that isRegistered new returns true
    await expect(client.isRegistered()).resolves.toBe(true)
  })
})

describe('#changeVaultPassword', () => {
  it('changes remote password and updates cache', async () => {
    const { client, remoteClient } = getClient()

    await client.register(kdk, password)

    // create a vault through the caching client so it is cached
    await client.createVault(kdk, password, b`A`, '', '')

    // change vault password through the caching client
    const newPassword = b`NewPassword`
    await client.changeVaultPassword(kdk, password, newPassword)

    // vaults should be retrieved using new password
    await expect(client.listVaults(kdk, newPassword)).resolves.toHaveLength(1)

    // vaults should be retrieved from remote service using new password
    await expect(
      remoteClient.listVaults(kdk, newPassword),
    ).resolves.toHaveLength(1)
  })

  it('fails when offline', async () => {
    const { client, remoteClient } = getClient()

    await client.register(kdk, password)

    remoteClient.changeVaultPassword = jest
      .fn()
      .mockRejectedValue(new OfflineError())

    await expect(
      client.changeVaultPassword(kdk, password, b`NewPassword`),
    ).rejects.toThrowError(OfflineError)
  })
})

describe('#reset', () => {
  it('clears registration state', async () => {
    const { client } = getClient()
    await client.register(kdk, password)

    client.reset()

    await expect(client.isRegistered()).resolves.toBe(false)
  })
})

describe('#deregister', () => {
  it('clears registration state', async () => {
    const { client } = getClient()
    await client.register(kdk, password)

    await client.deregister()

    await expect(client.isRegistered()).resolves.toBe(false)
  })

  it('resets remote service and cache', async () => {
    const client = new CachingSudoSecureVaultClient(
      new LocalSudoSecureVaultClient({
        databaseName: 'remote-client',
        pbkdfRounds: 5000,
      }),
      new LocalSudoSecureVaultClient({
        databaseName: 'cache-client',
        pbkdfRounds: 5000,
      }),
      (a, _b) => a,
      () => void 0 /* ignore not registered error */,
    )

    await client.register(kdk, password)

    // create a vault through the caching client so it is cached
    await client.createVault(kdk, password, b`A`, '', '')

    await client.deregister()

    await expect(client.listVaults(kdk, password)).rejects.toThrowError(
      NotRegisteredError,
    )
  })
})
