import { PasswordManagerClient } from './passwordManagerClient'
import { VaultNotUnlockedError } from './errors'
import { getDocument } from 'pdfjs-dist'
import { getMockClient } from './utils/testing/mockClient'
import { RescueKitTemplate } from './utils/rescueKitTemplate'

// Override pdfjs-dist with es5 version.  The regular package does not
// inlclude a poly/pony fill for ReadableStream.
// https://github.com/mozilla/pdf.js/issues/11762#issuecomment-605720752
jest.mock('pdfjs-dist', () => require('pdfjs-dist/es5/build/pdf'))

let client: PasswordManagerClient

beforeEach(() => {
  client = getMockClient().client
})

describe('#renderRescueKit', () => {
  it('fills the pdf with the secret code', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)
    const expectedSecretCode = await client.showSecretCode()

    const results = await client.renderRescueKit()

    const resultsDocument = await getDocument({
      data: results,
    }).promise
    expect(resultsDocument.numPages).toEqual(1)
    const firstPage = await resultsDocument.getPage(1)
    expect(firstPage.pageNumber).toEqual(1)
    const textContents = await firstPage.getTextContent()

    // Make sure the secret code text is in the page
    const secretCodeTextItem = textContents.items.find(
      (item) => item.str === expectedSecretCode,
    )
    expect(secretCodeTextItem).toHaveProperty('str', expectedSecretCode)
  })

  it('fills a custom template with the secret code', async () => {
    await client.register('P@ssw0rd!')
    expect(client.isLocked()).toBe(false)
    const expectedSecretCode = await client.showSecretCode()

    const results = await client.renderRescueKit({
      pdfTemplate: RescueKitTemplate,
    })

    const resultsDocument = await getDocument({
      data: results,
    }).promise
    expect(resultsDocument.numPages).toEqual(1)
    const firstPage = await resultsDocument.getPage(1)
    expect(firstPage.pageNumber).toEqual(1)
    const textContents = await firstPage.getTextContent()

    // Make sure the secret code text is in the page
    const secretCodeTextItem = textContents.items.find(
      (item) => item.str === expectedSecretCode,
    )
    expect(secretCodeTextItem).toHaveProperty('str', expectedSecretCode)
  })

  it('fails when vaults are locked', async () => {
    await client.register('P@ssw0rd!')
    const vault = await client.createVault('')
    expect(vault.id).toBeTruthy()

    client.lock()

    await expect(client.renderRescueKit()).rejects.toThrow(
      VaultNotUnlockedError,
    )
  })
})
