import { normalizeMasterPassword } from './normalizeMasterPassword'

it('trims leading and trailing whitespace', () => {
  expect(normalizeMasterPassword(' hello ')).toEqual('hello')
  expect(normalizeMasterPassword('\nhello\t')).toEqual('hello')
  expect(normalizeMasterPassword('h ello')).toEqual('h ello')
})

it.each([
  '\u{212B}', // 'Å' ANGSTROM SIGN
  '\u{00C5}', // 'Å' LATIN CAPITAL LETTER A WITH RING ABOVE
  '\u{0041}\u{030A}', // 'A' LATIN CAPITAL LETTER A + '°' COMBINING RING ABOVE
])('performs unicode normalization', (character) => {
  expect(normalizeMasterPassword(`h${character}llo`)).toEqual(
    'h\u{0041}\u{030A}llo',
  )
})
