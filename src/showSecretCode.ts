import { PasswordManagerClient } from './passwordManagerClient'
import { passwordManagerCryptoProvider as cryptoProvider } from './runtimes/node/node-password-manager-crypto'
import { zerofill } from './utils/zerofill'

/**
 * @see {@link PasswordManagerClient.showSecretCode}
 */
export async function showSecretCode(
  this: PasswordManagerClient,
): Promise<string> {
  const keyDerivingKey = await this.unsafeGetKeyDerivingKey()
  const secretCode = Array.from(new Uint8Array(keyDerivingKey))
    .map((value) => value.toString(16).padStart(2, '0'))
    .join('')
    .replace(
      /(......)(.....)(.....)(.....)(.....)(......)/,
      '$1-$2-$3-$4-$5-$6',
    )
  zerofill(keyDerivingKey)

  const subject = this.sudoUserClient.getSubject()
  const hashedSubject = subject
    ? (await cryptoProvider.hashSubject(subject)).substr(0, 5)
    : '00000'

  return (hashedSubject + '-' + secretCode).toUpperCase()
}
