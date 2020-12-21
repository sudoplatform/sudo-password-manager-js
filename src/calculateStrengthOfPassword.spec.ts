import { PasswordStrength } from './types'
import { calculateStrengthOfPassword } from './calculateStrengthOfPassword'

describe('#calculateStrengthOfPassword', () => {
  test('very weak password', () => {
    const strength = calculateStrengthOfPassword('password')
    expect(strength).toEqual(PasswordStrength.VeryWeak)
  })

  test('weak password', () => {
    const strength = calculateStrengthOfPassword('weakpassword')
    expect(strength).toEqual(PasswordStrength.Weak)
  })

  test('moderate password', () => {
    const strength = calculateStrengthOfPassword('ModeratePassword123')
    expect(strength).toEqual(PasswordStrength.Moderate)
  })

  test('strong password', () => {
    const strength = calculateStrengthOfPassword('StrongPassword123!?')
    expect(strength).toEqual(PasswordStrength.Strong)
  })

  test('very strong password', () => {
    const strength = calculateStrengthOfPassword('#$VeryStrongPassword123!?')
    expect(strength).toEqual(PasswordStrength.VeryStrong)
  })
})
