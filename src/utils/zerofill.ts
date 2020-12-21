/** zero-fills the provided `ArrayBuffer`. */
export const zerofill = (buffer: ArrayBuffer): void => {
  if (ArrayBuffer.isView(buffer)) {
    new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength).fill(0)
  } else {
    new Uint8Array(buffer).fill(0)
  }
}
