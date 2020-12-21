require('fake-indexeddb/auto')
// eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-unsafe-assignment
const FDBFactory = require('fake-indexeddb/lib/FDBFactory')

import {
  NotAuthorizedError,
  NotRegisteredError,
  VersionMismatchError,
} from '@sudoplatform/sudo-common'
import { InvalidVaultError } from '@sudoplatform/sudo-secure-vault'
import {
  LocalSudoSecureVaultClient,
  SecureVaultAlreadyRegisteredError,
} from './local-secure-vault-service'

afterEach(() => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
  indexedDB = new FDBFactory()
})

describe('#register', () => {
  it('starts out unregistered', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    await expect(service.isRegistered()).resolves.toBe(false)
  })

  it('registers', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    await service.register(new Uint8Array([24]), new Uint8Array([42]))
    await expect(service.isRegistered()).resolves.toBe(true)
  })

  it('prevents duplicate registration', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })

    // race two registration attempts against each other
    await expect(
      Promise.all([
        service.register(new Uint8Array([24]), new Uint8Array([42])),
        service.register(new Uint8Array([55]), new Uint8Array([55])), // 5
      ]),
    ).rejects.toThrowError(SecureVaultAlreadyRegisteredError)

    // although one attempt failed, the other should successfully register
    await expect(service.isRegistered()).resolves.toBe(true)
  })
})

describe('#createVault', () => {
  it('creates a vault', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)

    const rawBlob = new Uint8Array([1, 2, 3, 4, 5])

    const vault = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      rawBlob,
      'format',
      'proof',
    )

    expect(vault.id).toBeTruthy()
    expect(vault.version).toEqual(0)
    expect(vault.blobFormat).toEqual('format')
    expect(vault.createdAt).toBeTruthy()
    expect(vault.updatedAt).toBeTruthy()
    expect(vault.owner).toBeTruthy()
    expect(vault.owners.length).toBeGreaterThan(0)
  })

  it('fails when the user is not registered', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })

    await expect(
      service.createVault(
        new Uint8Array([42]),
        new Uint8Array([42]),
        new Uint8Array([42]),
        'format',
        'proof',
      ),
    ).rejects.toThrowError(NotRegisteredError)
  })

  it('fails when key does not match registered', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])

    await service.register(keyDerivingKey, vaultPassword)

    await expect(
      service.createVault(
        new Uint8Array([555, 55]), // <-- uses the wrong key deriving key
        vaultPassword,
        new Uint8Array([1, 2, 3, 4, 5]),
        'format',
        'proof',
      ),
    ).rejects.toThrowError(NotAuthorizedError)
  })

  it.todo('fails when ownership proof is invalid')
})

describe('#getVault', () => {
  it('retrieves a vault', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)
    const rawBlob = new Uint8Array([1, 2, 3, 4, 5])

    const { id } = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      rawBlob,
      'format',
      'proof',
    )

    const vault = await service.getVault(keyDerivingKey, vaultPassword, id)

    if (!vault) fail('vault should be defined')
    expect(vault.id).toBeTruthy()
    expect(vault.version).toEqual(0)
    expect(vault.blob).toEqual(rawBlob)
    expect(vault.blobFormat).toEqual('format')
    expect(vault.createdAt).toBeTruthy()
    expect(vault.updatedAt).toBeTruthy()
  })

  it('fails when the user is not registered', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })

    await expect(
      service.getVault(new Uint8Array([42]), new Uint8Array([42]), '....'),
    ).rejects.toThrowError(NotRegisteredError)
  })

  it('fails when key is incorrect', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)
    const rawBlob = new Uint8Array([1, 2, 3, 4, 5])

    const { id } = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      rawBlob,
      'format',
      'proof',
    )

    await expect(
      service.getVault(new Uint8Array(), vaultPassword, id),
    ).rejects.toThrowError(NotAuthorizedError)
  })

  it('fails when password is incorrect', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)
    const rawBlob = new Uint8Array([1, 2, 3, 4, 5])

    const { id } = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      rawBlob,
      'format',
      'proof',
    )

    const bad = new Uint8Array([91, 91, 91])
    await expect(
      service.getVault(keyDerivingKey, bad, id),
    ).rejects.toThrowError(NotAuthorizedError)
  })

  it('returns undefined when vault does not exist', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)

    await expect(
      service.getVault(keyDerivingKey, vaultPassword, ''),
    ).resolves.toBeUndefined()
  })
})

describe('#updateVault', () => {
  it('updates a vault', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)
    const rawBlob = new Uint8Array([1, 2, 3, 4, 5])
    const vault = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      rawBlob,
      'format',
      'proof',
    )

    const newRawBlob = new Uint8Array([6, 7, 8, 9, 10])
    const newVersion = 1
    const newBlobFormat = 'new format'

    await service.updateVault(
      keyDerivingKey,
      vaultPassword,
      vault.id,
      vault.version,
      newRawBlob,
      newBlobFormat,
    )

    const updatedVault = await service.getVault(
      keyDerivingKey,
      vaultPassword,
      vault.id,
    )

    if (!updatedVault) fail('updated vault should be defined')
    expect(updatedVault.id).toEqual(vault.id)
    expect(updatedVault.blob).toEqual(newRawBlob)
    expect(updatedVault.blobFormat).toEqual(newBlobFormat)
    expect(updatedVault.version).toEqual(newVersion)
    expect(updatedVault.createdAt).toEqual(vault.createdAt)
    expect(updatedVault.updatedAt.getTime()) //
      .toBeGreaterThan(vault.updatedAt.getTime())
  })

  it('fails when the user is not registered', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })

    await expect(
      service.updateVault(
        new Uint8Array([42]),
        new Uint8Array([42]),
        '....',
        0,
        new Uint8Array([55]),
        '',
      ),
    ).rejects.toThrowError(NotRegisteredError)
  })

  it('fails when key is incorrect', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)
    const rawBlob = new Uint8Array([1, 2, 3, 4, 5])
    const vault = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      rawBlob,
      'format',
      'proof',
    )

    const newRawBlob = new Uint8Array([6, 7, 8, 9, 10])
    const newVersion = 2
    const newBlobFormat = 'new format'

    await expect(
      service.updateVault(
        new Uint8Array(),
        vaultPassword,
        vault.id,
        newVersion,
        newRawBlob,
        newBlobFormat,
      ),
    ).rejects.toThrowError(NotAuthorizedError)
  })

  it('fails when password is incorrect', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)
    const rawBlob = new Uint8Array([1, 2, 3, 4, 5])
    const vault = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      rawBlob,
      'format',
      'proof',
    )

    const newRawBlob = new Uint8Array([6, 7, 8, 9, 10])
    const newVersion = 2
    const newBlobFormat = 'new format'

    await expect(
      service.updateVault(
        keyDerivingKey,
        new Uint8Array([91, 91, 91]),
        vault.id,
        newVersion,
        newRawBlob,
        newBlobFormat,
      ),
    ).rejects.toThrowError(NotAuthorizedError)
  })

  it('fails upon version mismatch', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)
    const rawBlob = new Uint8Array([1, 2, 3, 4, 5])
    const vault = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      rawBlob,
      'format',
      'proof',
    )

    const newRawBlob = new Uint8Array([6, 7, 8, 9, 10])
    const newVersion = -1
    const newBlobFormat = 'new format'

    await expect(
      service.updateVault(
        keyDerivingKey,
        vaultPassword,
        vault.id,
        newVersion,
        newRawBlob,
        newBlobFormat,
      ),
    ).rejects.toThrowError(VersionMismatchError)
  })

  it('fails when vault does not exist', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)

    const newRawBlob = new Uint8Array([6, 7, 8, 9, 10])
    const newVersion = 2
    const newBlobFormat = 'new format'

    await expect(
      service.updateVault(
        keyDerivingKey,
        vaultPassword,
        '',
        newVersion,
        newRawBlob,
        newBlobFormat,
      ),
    ).rejects.toThrowError(InvalidVaultError)
  })
})

describe('#deleteVault', () => {
  it('deletes a vault', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)
    const rawBlob = new Uint8Array([1, 2, 3, 4, 5])
    const vault = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      rawBlob,
      'format',
      'proof',
    )

    await service.deleteVault(vault.id)

    // vault should no longer be retrieved
    await expect(
      service.getVault(keyDerivingKey, vaultPassword, vault.id),
    ).resolves.toBeUndefined()
  })

  it('fails when the user is not registered', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })

    await expect(service.deleteVault('....')).rejects.toThrowError(
      NotRegisteredError,
    )
  })

  it('fails when vault does not exist', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    await service.register(new Uint8Array([42]), new Uint8Array([42]))
    await expect(service.deleteVault('')).rejects.toThrowError(
      InvalidVaultError,
    )
  })
})

describe('#listVaults', () => {
  it('filters vaults by key and password', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)

    const vault1 = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      new Uint8Array([1998]),
      'format',
      'proof',
    )

    const rawBlob2 = new Uint8Array(
      JSON.parse('[78,69,86,69,82,32,71,79,78,78,65,32,71,73,86,69]'),
    )
    const vault2 = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      rawBlob2,
      'format',
      'proof',
    )

    const list = await service.listVaults(keyDerivingKey, vaultPassword)
    expect(list).toHaveLength(2)
    expect(list).toContainEqual(expect.objectContaining(vault1))
    expect(list).toContainEqual(expect.objectContaining(vault2))
  })

  it('fails when the user is not registered', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })

    await expect(
      service.listVaults(new Uint8Array([42]), new Uint8Array([42])),
    ).rejects.toThrowError(NotRegisteredError)
  })

  it('fails when key is incorrect', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)

    await expect(
      service.listVaults(new Uint8Array([42]), vaultPassword),
    ).rejects.toThrowError(NotAuthorizedError)
  })

  it('fails when password is incorrect', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)

    await expect(
      service.listVaults(keyDerivingKey, new Uint8Array([42])),
    ).rejects.toThrowError(NotAuthorizedError)
  })
})

describe('#listVaultsMetadataOnly', () => {
  it('lists vault metadata', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const vaultPassword = new Uint8Array([65, 65, 65])
    await service.register(keyDerivingKey, vaultPassword)

    const created1 = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      new Uint8Array([1, 2, 3, 4, 5]),
      'format',
      'proof:audience.proof',
    )

    const created2 = await service.createVault(
      keyDerivingKey,
      vaultPassword,
      new Uint8Array([6, 7, 8, 9, 10]),
      'other format',
      'other proof:audience.other proof',
    )

    const metadata = await service.listVaultsMetadataOnly()

    expect(metadata).toHaveLength(2)
    expect(metadata).toContainEqual({
      id: created1.id,
      version: 0,
      blobFormat: 'format',
      createdAt: created1.createdAt,
      updatedAt: created1.updatedAt,
      owner: 'proof',
      owners: [{ id: 'proof', issuer: 'audience.proof' }],
    })
    expect(metadata).toContainEqual({
      id: created2.id,
      version: 0,
      blobFormat: 'other format',
      createdAt: created2.createdAt,
      updatedAt: created2.updatedAt,
      owner: 'other proof',
      owners: [{ id: 'other proof', issuer: 'audience.other proof' }],
    })
  })

  it('fails when the user is not registered', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })

    await expect(service.listVaultsMetadataOnly()).rejects.toThrowError(
      NotRegisteredError,
    )
  })
})

describe('#changeVaultPassword', () => {
  it('changes vault password', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    const keyDerivingKey = new Uint8Array([42, 24])
    const oldVaultPassword = new Uint8Array([65, 65, 65])

    // register and create a vault with the old password
    await service.register(keyDerivingKey, oldVaultPassword)

    const vault1 = await service.createVault(
      keyDerivingKey,
      oldVaultPassword,
      new Uint8Array([1, 2, 3, 4, 5]),
      'format',
      'proof',
    )

    const newVaultPassword = new Uint8Array([96, 96, 96])

    // sanity check that using the new password before changing fails
    await expect(
      service.getVault(keyDerivingKey, newVaultPassword, vault1.id),
    ).rejects.toThrowError(NotAuthorizedError)

    await expect(
      service.getVault(keyDerivingKey, oldVaultPassword, vault1.id),
    ).resolves.toEqual(expect.objectContaining(vault1))

    // change the password
    await service.changeVaultPassword(
      keyDerivingKey,
      oldVaultPassword,
      newVaultPassword,
    )

    // ensure that the new password works now and the old password fails
    await expect(
      service.getVault(keyDerivingKey, newVaultPassword, vault1.id),
    ).resolves.toEqual(expect.objectContaining(vault1))

    await expect(
      service.getVault(keyDerivingKey, oldVaultPassword, vault1.id),
    ).rejects.toThrowError(NotAuthorizedError)
  })

  it('fails when the user is not registered', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    await expect(
      service.changeVaultPassword(
        new Uint8Array([42]),
        new Uint8Array([42]),
        new Uint8Array([42]),
      ),
    ).rejects.toThrowError(NotRegisteredError)
  })

  it.todo('fails when an update occurs mid-change')
})

describe('#deregister', () => {
  it('deregisters', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })

    await service.register(new Uint8Array([0]), new Uint8Array([0]))
    await expect(service.isRegistered()).resolves.toBe(true)
    await expect(service.getInitializationData()).resolves.toBeDefined()

    await service.deregister()
    await expect(service.isRegistered()).resolves.toBe(false)
    await expect(service.getInitializationData()).resolves.toBeUndefined()
  })

  it('is idempotent', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    await expect(service.isRegistered()).resolves.toBe(false)
    await service.deregister()
    await expect(service.isRegistered()).resolves.toBe(false)
  })

  it('allows registering after deregistering', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })

    await service.register(new Uint8Array([0]), new Uint8Array([0]))
    await expect(service.isRegistered()).resolves.toBe(true)

    await service.deregister()
    await expect(service.isRegistered()).resolves.toBe(false)

    await service.register(new Uint8Array([1]), new Uint8Array([1]))
    await expect(service.isRegistered()).resolves.toBe(true)
  })
})

describe('#resets', () => {
  it('resets', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })

    await service.register(new Uint8Array([0]), new Uint8Array([0]))
    await expect(service.isRegistered()).resolves.toBe(true)
    await expect(service.getInitializationData()).resolves.toBeDefined()

    service.reset()
    await expect(service.isRegistered()).resolves.toBe(false)
    await expect(service.getInitializationData()).resolves.toBeUndefined()
  })

  it('is idempotent', async () => {
    const service = new LocalSudoSecureVaultClient({ pbkdfRounds: 5000 })
    await expect(service.isRegistered()).resolves.toBe(false)
    service.reset()
    await expect(service.isRegistered()).resolves.toBe(false)
  })
})
