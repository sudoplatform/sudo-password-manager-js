import * as crypto from 'crypto'

/**
 * Returns a random number between zero and the upper bound (exclusive)
 * @param upperBoundExclusive The upper bound of the random number to generate, must be <= 255
 */
export function secureRandomNumber(upperBoundExclusive: number): number {
  const byteBuffer = new Uint8Array(1)
  let randomArrayIndex
  do {
    crypto.randomFillSync(byteBuffer)
    randomArrayIndex = byteBuffer[0]
  } while (randomArrayIndex >= 255 - (255 % upperBoundExclusive))
  return randomArrayIndex % upperBoundExclusive
}
