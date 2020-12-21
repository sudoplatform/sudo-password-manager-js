import { generatePassword } from './generatePassword'

describe('#generatePassword', () => {
  test('default parameters', () => {
    const password = generatePassword()
    // check password length
    expect(password).toHaveLength(20)
    // check for at least one of each character type
    expect(password).toMatch(/[A-Z]/)
    expect(password).toMatch(/[a-z]/)
    expect(password).toMatch(/[2-9]/)
    expect(password).toMatch(/[!?@*._-]/)
  })

  test('set length', () => {
    const password = generatePassword({ length: 25 })
    expect(password).toHaveLength(25)
  })

  test('set min length', () => {
    const password = generatePassword({ length: 0 })
    expect(password).toHaveLength(6)
  })

  test('exclude uppercase', () => {
    const password = generatePassword({
      allowUppercase: false,
    })
    expect(password).not.toMatch(/[A-Z]/)
    expect(password).toMatch(/[a-z]/)
    expect(password).toMatch(/[2-9]/)
    expect(password).toMatch(/[!?@*._-]/)
  })

  test('exclude lowercase', () => {
    const password = generatePassword({
      allowLowercase: false,
    })
    expect(password).toMatch(/[A-Z]/)
    expect(password).not.toMatch(/[a-z]/)
    expect(password).toMatch(/[2-9]/)
    expect(password).toMatch(/[!?@*._-]/)
  })

  test('exclude numbers', () => {
    const password = generatePassword({
      allowNumbers: false,
    })
    expect(password).toMatch(/[A-Z]/)
    expect(password).toMatch(/[a-z]/)
    expect(password).not.toMatch(/[2-9]/)
    expect(password).toMatch(/[!?@*._-]/)
  })

  test('exclude symbols', () => {
    const password = generatePassword({
      allowSymbols: false,
    })
    expect(password).toMatch(/[A-Z]/)
    expect(password).toMatch(/[a-z]/)
    expect(password).toMatch(/[2-9]/)
    expect(password).not.toMatch(/[!?@*._-]/)
  })

  test('exclude all', () => {
    // excluding all should enable all
    const password = generatePassword({
      allowUppercase: false,
      allowLowercase: false,
      allowNumbers: false,
      allowSymbols: false,
    })
    expect(password).toMatch(/[A-Z]/)
    expect(password).toMatch(/[a-z]/)
    expect(password).toMatch(/[2-9]/)
    expect(password).toMatch(/[!?@*._-]/)
  })

  test('no ambiguous characters', () => {
    // check multiple passwords to ensure the ambiguous characters are never included
    for (let i = 0; i < 20; i++) {
      const password = generatePassword({ length: 50 })
      expect(password).not.toMatch(/[oO0lI1]/)
    }
  })
})
