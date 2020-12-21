import { PasswordStrength } from './types'
import zxcvbn from 'zxcvbn'

/**
 * Calculate strength of a password
 * @param password The password string to calculate
 * @returns A `PasswordStrength` indicating the strength of the passed in password
 */
export function calculateStrengthOfPassword(
  password: string,
): PasswordStrength {
  switch (zxcvbn(password).score) {
    case 0:
      return PasswordStrength.VeryWeak
    case 1:
      return PasswordStrength.Weak
    case 2:
      return PasswordStrength.Moderate
    case 3:
      return PasswordStrength.Strong
    case 4:
      return PasswordStrength.VeryStrong
    default:
      return PasswordStrength.VeryWeak
  }
}
