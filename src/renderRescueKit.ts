import { PDFDocument, StandardFonts } from 'pdf-lib'
import { PasswordManagerClient } from './passwordManagerClient'
import { RescueKitTemplate } from './utils/rescueKitTemplate'
import { VaultNotUnlockedError } from './errors'

/**
 * Optional Properties for rendering the rescue kit.
 */
export interface RenderRescueKitProps {
  /**
   * The pdf template to use to fill the secret code.
   * Will default to the sudo platform template.
   */
  pdfTemplate?: ArrayBuffer
}

/**
 * @see {@link PasswordManagerClient.renderRescueKit}
 */
export async function renderRescueKit(
  this: PasswordManagerClient,
  { pdfTemplate = RescueKitTemplate }: RenderRescueKitProps = {},
): Promise<ArrayBuffer> {
  if (this.isLocked()) throw new VaultNotUnlockedError()

  const secretCode = await this.showSecretCode()

  const pdfDoc = await PDFDocument.load(pdfTemplate)
  const font = await pdfDoc.embedFont(StandardFonts.CourierBold)
  const [firstPage] = pdfDoc.getPages()

  firstPage.drawText(secretCode, {
    x: 70,
    y: 150,
    size: 18,
    font,
  })

  // Set metadata for the PDF document
  pdfDoc.setTitle('Sudo Platform Rescue Kit')
  pdfDoc.setSubject('Sudo Platform Rescue Kit')
  pdfDoc.setCreator('Sudo Platform')
  pdfDoc.setCreationDate(new Date())

  const pdfData = await pdfDoc.save()
  return pdfData.buffer
}
