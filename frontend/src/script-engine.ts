import { PacketReader, type ParsedField } from './packet-reader'

export interface ParseResult {
  success: boolean
  fields: ParsedField[]
  error?: string
}

export function executeScript(hexDump: string, scriptCode: string): ParseResult {
  const reader = new PacketReader(hexDump)
  try {
    const fn = new Function('packet', scriptCode)
    fn(reader)
    return { success: true, fields: reader.getFields() }
  } catch (e: any) {
    return {
      success: false,
      fields: reader.getFields(),
      error: e?.message || String(e)
    }
  }
}
