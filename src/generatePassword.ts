import { secureRandomNumber } from './runtimes/node/node-secure-random-number'

/** Options used to customize passwords produced by `generatePassword`. */
export interface GeneratePasswordOptions {
  /** The number of characters in the generated password. Must be >= 6 */
  length?: number
  /** Whether the password should contain at least one uppercase letter (O and I excluded) */
  allowUppercase?: boolean
  /** Whether the password should contain at least one lowercase letter (o and l excluded) */
  allowLowercase?: boolean
  /** Whether the password should contain at least one number (0 and 1 excluded) */
  allowNumbers?: boolean
  /** Whether the password should contain at least one of the symbols "!?@*._-" */
  allowSymbols?: boolean
}

/**
 * @see {@link PasswordManagerClient.generatePassword}
 */
export function generatePassword({
  length = 20,
  allowUppercase = true,
  allowLowercase = true,
  allowNumbers = true,
  allowSymbols = true,
}: GeneratePasswordOptions = {}): string {
  const allAllowed =
    !allowUppercase && !allowLowercase && !allowNumbers && !allowSymbols

  // add possible characters excluding ambiguous characters `oO0lI1`
  const uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  const lowercase = 'abcdefghijkmnpqrstuvwxyz'
  const numbers = '23456789'
  const symbols = '!?@*._-'

  let allPossibleCharacters = ''
  let password = ''

  if (allowUppercase || allAllowed) {
    allPossibleCharacters += uppercase
    // add one character from this set to ensure there is at least one
    password += uppercase.charAt(secureRandomNumber(uppercase.length))
  }

  if (allowLowercase || allAllowed) {
    allPossibleCharacters += lowercase
    // add one character from this set to ensure there is at least one
    password += lowercase.charAt(secureRandomNumber(lowercase.length))
  }

  if (allowNumbers || allAllowed) {
    allPossibleCharacters += numbers
    // add one character from this set to ensure there is at least one
    password += numbers.charAt(secureRandomNumber(numbers.length))
  }

  if (allowSymbols || allAllowed) {
    allPossibleCharacters += symbols
    // add one character from this set to ensure there is at least one
    password += symbols.charAt(secureRandomNumber(symbols.length))
  }

  // restrict length to greater than or equal to 6
  const finalLength = Math.max(length, 6)

  // generate password
  const charactersRemaining = finalLength - password.length
  for (let i = 0; i < charactersRemaining; i++) {
    const character = allPossibleCharacters.charAt(
      secureRandomNumber(allPossibleCharacters.length),
    )
    password += character
  }
  // shuffle the password so it doesn't always start with uppercase->lowercase->etc..
  const passwordCharacters = password.split('')
  for (let i = passwordCharacters.length - 1; i >= 0; i--) {
    const randomIndex = secureRandomNumber(i + 1)
    const temp = passwordCharacters[i]
    passwordCharacters[i] = passwordCharacters[randomIndex]
    passwordCharacters[randomIndex] = temp
  }
  return passwordCharacters.join('')
}
