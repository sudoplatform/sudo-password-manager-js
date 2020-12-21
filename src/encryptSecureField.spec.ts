import { passwordManagerCryptoProvider } from './runtimes/node/node-password-manager-crypto'
import { encryptSecureField, decryptSecureField } from './encryptSecureField'
import { SecureField } from './gen/schema-types'

it('can decrypt its own encrypted values', async () => {
  const keyDerivingKey = await passwordManagerCryptoProvider.generateKeyDerivingKey()
  const plaintext = 'hello world مرحبا بالعالم'

  const secureField = await encryptSecureField(keyDerivingKey, plaintext)
  expect(secureField.secureValue).not.toEqual(plaintext)

  const decrypted = await decryptSecureField(keyDerivingKey, secureField)
  expect(decrypted).toEqual(plaintext)
})

it('fails when reveal key is incorrect', async () => {
  const keyDerivingKey = await passwordManagerCryptoProvider.generateKeyDerivingKey()
  const plaintext = 'hello world مرحبا بالعالم'

  const secureField = await encryptSecureField(keyDerivingKey, plaintext)
  expect(secureField.secureValue).not.toEqual(plaintext)

  await expect(decryptSecureField(new Uint8Array([42]), secureField)) //
    .rejects.toThrow()
})

it('fails when message has been tampered with', async () => {
  const keyDerivingKey = await passwordManagerCryptoProvider.generateKeyDerivingKey()
  const plaintext = 'hello world مرحبا بالعالم'

  const secureField = await encryptSecureField(keyDerivingKey, plaintext)

  // tamper with the value of secureField
  const tamperedSecureField: SecureField = {
    secureValue: secureField.secureValue.replace(/[aeiouAEIOU]/g, 'h'),
  }

  await expect(decryptSecureField(keyDerivingKey, tamperedSecureField)) //
    .rejects.toThrow()
})
