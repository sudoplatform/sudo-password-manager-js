/**
 * Transforms the provided password to avoid common problems from user input.
 * 1. Strips leading and trailing whitespace from the string.
 * 2. Performs NFKD unicode normalization.
 * @param password password to normalize
 * @returns normalized password
 */
export function normalizeMasterPassword(password: string): string {
  return password.trim().normalize('NFKD')
}
