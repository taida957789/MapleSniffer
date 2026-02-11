export interface ParsedField {
  name: string
  type: string // "byte" | "short" | "int" | "long" | "string" | "bytes" | "object" | "array"
  value: any
  offset: number
  length: number
  children?: ParsedField[]
}

export class PacketReader {
  private data: Uint8Array
  private pos: number = 0
  private fields: ParsedField[] = []
  private fieldStack: ParsedField[][] = []

  constructor(hexDump: string) {
    // Parse hex string (space-separated or continuous) into Uint8Array
    // Handle multi-line hex dumps: strip offset prefixes and ASCII columns
    const bytes: number[] = []
    const lines = hexDump.split('\n')
    for (const line of lines) {
      // Match hex bytes (pairs of hex chars separated by spaces)
      const matches = line.match(/(?:^[\da-fA-F]+:\s+)?([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)/)
      if (matches) {
        const hexPart = matches[1]
        for (const pair of hexPart.split(/\s+/)) {
          if (pair.length === 2 && /^[0-9a-fA-F]{2}$/.test(pair)) {
            bytes.push(parseInt(pair, 16))
          }
        }
      }
    }
    this.data = new Uint8Array(bytes)
    this.fieldStack = [this.fields]
  }

  private currentFields(): ParsedField[] {
    return this.fieldStack[this.fieldStack.length - 1]
  }

  private addField(field: ParsedField): void {
    this.currentFields().push(field)
  }

  private ensureBytes(n: number): void {
    if (this.pos + n > this.data.length) {
      throw new Error(`Read past end: need ${n} bytes at offset ${this.pos}, but only ${this.data.length - this.pos} remaining`)
    }
  }

  readByte(name: string): number {
    this.ensureBytes(1)
    const offset = this.pos
    const value = this.data[this.pos++]
    this.addField({ name, type: 'byte', value, offset, length: 1 })
    return value
  }

  readShort(name: string): number {
    this.ensureBytes(2)
    const offset = this.pos
    const value = this.data[this.pos] | (this.data[this.pos + 1] << 8)
    this.pos += 2
    this.addField({ name, type: 'short', value, offset, length: 2 })
    return value
  }

  readInt(name: string): number {
    this.ensureBytes(4)
    const offset = this.pos
    const value = (this.data[this.pos]
      | (this.data[this.pos + 1] << 8)
      | (this.data[this.pos + 2] << 16)
      | (this.data[this.pos + 3] << 24)) >>> 0 // unsigned
    this.pos += 4
    this.addField({ name, type: 'int', value, offset, length: 4 })
    return value
  }

  readLong(name: string): bigint {
    this.ensureBytes(8)
    const offset = this.pos
    let value = BigInt(0)
    for (let i = 0; i < 8; i++) {
      value |= BigInt(this.data[this.pos + i]) << BigInt(i * 8)
    }
    this.pos += 8
    this.addField({ name, type: 'long', value: value.toString(), offset, length: 8 })
    return value
  }

  readString(name: string): string {
    this.ensureBytes(2)
    const offset = this.pos
    const len = this.data[this.pos] | (this.data[this.pos + 1] << 8)
    this.pos += 2
    this.ensureBytes(len)
    const bytes = this.data.slice(this.pos, this.pos + len)
    const value = new TextDecoder().decode(bytes)
    this.pos += len
    this.addField({ name, type: 'string', value, offset, length: 2 + len })
    return value
  }

  readBytes(name: string, len: number): Uint8Array {
    this.ensureBytes(len)
    const offset = this.pos
    const value = this.data.slice(this.pos, this.pos + len)
    this.pos += len
    const hexStr = Array.from(value).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
    this.addField({ name, type: 'bytes', value: hexStr, offset, length: len })
    return value
  }

  readObject(name: string, fn: (r: PacketReader) => void): void {
    const offset = this.pos
    const children: ParsedField[] = []
    const field: ParsedField = { name, type: 'object', value: null, offset, length: 0, children }
    this.addField(field)
    this.fieldStack.push(children)
    fn(this)
    this.fieldStack.pop()
    field.length = this.pos - offset
  }

  readArray(name: string, count: number | null, fn: (r: PacketReader, i: number) => void): void {
    const offset = this.pos
    let actualCount: number
    if (count === null) {
      // Read count as short
      this.ensureBytes(2)
      actualCount = this.data[this.pos] | (this.data[this.pos + 1] << 8)
      this.pos += 2
    } else {
      actualCount = count
    }
    const children: ParsedField[] = []
    const field: ParsedField = {
      name: `${name} [${actualCount}]`,
      type: 'array',
      value: actualCount,
      offset,
      length: 0,
      children
    }
    this.addField(field)
    this.fieldStack.push(children)
    for (let i = 0; i < actualCount; i++) {
      fn(this, i)
    }
    this.fieldStack.pop()
    field.length = this.pos - offset
  }

  skip(name: string, len: number): void {
    this.ensureBytes(len)
    const offset = this.pos
    const value = this.data.slice(this.pos, this.pos + len)
    const hexStr = Array.from(value).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
    this.pos += len
    this.addField({ name, type: 'bytes', value: hexStr, offset, length: len })
  }

  remaining(): number {
    return this.data.length - this.pos
  }

  position(): number {
    return this.pos
  }

  getFields(): ParsedField[] {
    return this.fields
  }
}
