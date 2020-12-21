import { zerofill } from './zerofill'

it('zero fills a Uint8Array view of an ArrayBuffer', () => {
  const buffer = new Uint8Array([42])
  expect(buffer.byteLength).toEqual(1)
  expect(buffer[0]).toEqual(42)

  zerofill(buffer)

  expect(buffer.byteLength).toEqual(1)
  expect(buffer[0]).toEqual(0)
})

it('zero fills a raw ArrayBuffer', () => {
  const buffer = new Uint8Array([42])
  expect(buffer.byteLength).toEqual(1)
  expect(buffer[0]).toEqual(42)

  zerofill(buffer.buffer)

  expect(buffer.byteLength).toEqual(1)
  expect(buffer[0]).toEqual(0)
})
