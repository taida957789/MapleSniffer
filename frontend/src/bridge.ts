export interface NetworkInterface {
  name: string
  friendlyName: string
  description: string
}

export interface PacketInfo {
  index: number
  timestamp: number
  length: number
  hexDump: string
  outbound: boolean
  opcode: string
  opcodeRaw: number
  isHandshake: boolean
  decrypted: boolean
  sessionId: number
  version?: number
  subVersion?: string
  locale?: number
}

export interface Status {
  capturing: boolean
  packetCount: number
  interface: string
  filter: string
}

export interface SessionMeta {
  id: number
  locale: number
  version: number
  subVersion: string
  serverPort: number
}

export interface ScriptEntry {
  direction: string
  opcode: number
  filename: string
}

const isSaucer = typeof (window as any).saucer !== 'undefined'

export async function getStatus(): Promise<Status> {
  if (isSaucer) return JSON.parse(await (window as any).saucer.exposed.getStatus())
  return (await fetch('/api/status')).json()
}

export async function getInterfaces(): Promise<NetworkInterface[]> {
  if (isSaucer) return JSON.parse(await (window as any).saucer.exposed.getInterfaces())
  return (await fetch('/api/interfaces')).json()
}

export async function getPackets(since: number): Promise<PacketInfo[]> {
  if (isSaucer) return JSON.parse(await (window as any).saucer.exposed.getPackets(since))
  return (await fetch(`/api/packets?since=${since}`)).json()
}

export async function startCapture(iface: string, filter: string): Promise<boolean> {
  if (isSaucer) return await (window as any).saucer.exposed.startCapture(iface, filter)
  const res = await fetch('/api/capture/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ interface: iface, filter })
  })
  const data = await res.json()
  return data.success
}

export async function stopCapture(): Promise<boolean> {
  if (isSaucer) return await (window as any).saucer.exposed.stopCapture()
  const res = await fetch('/api/capture/stop', { method: 'POST' })
  const data = await res.json()
  return data.success
}

export async function getSessions(): Promise<SessionMeta[]> {
  if (isSaucer) return JSON.parse(await (window as any).saucer.exposed.getSessions())
  return (await fetch('/api/sessions')).json()
}

export async function getScript(direction: string, opcode: number, locale: number, version: number): Promise<string> {
  if (isSaucer) return await (window as any).saucer.exposed.getScript(direction, opcode, locale, version)
  const res = await fetch(`/api/script?direction=${direction}&opcode=${opcode}&locale=${locale}&version=${version}`)
  return res.text()
}

export async function saveScript(direction: string, opcode: number, code: string, locale: number, version: number): Promise<boolean> {
  if (isSaucer) return await (window as any).saucer.exposed.saveScript(direction, opcode, code, locale, version)
  const res = await fetch('/api/script', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ direction, opcode, code, locale, version })
  })
  const data = await res.json()
  return data.success
}

export async function listScripts(locale: number, version: number): Promise<ScriptEntry[]> {
  if (isSaucer) return JSON.parse(await (window as any).saucer.exposed.listScripts(locale, version))
  return (await fetch(`/api/scripts?locale=${locale}&version=${version}`)).json()
}

// Opcode names
export interface OpcodeNameMap {
  send: Record<string, string>  // key = decimal opcode string, value = name
  recv: Record<string, string>
}

export async function getOpcodeNames(locale: number, version: number): Promise<OpcodeNameMap> {
  if (isSaucer) return JSON.parse(await (window as any).saucer.exposed.getOpcodeNames(locale, version))
  return (await fetch(`/api/opcode-names?locale=${locale}&version=${version}`)).json()
}

export async function saveOpcodeNames(locale: number, version: number, names: OpcodeNameMap): Promise<boolean> {
  const json = JSON.stringify(names)
  if (isSaucer) return await (window as any).saucer.exposed.saveOpcodeNames(locale, version, json)
  const res = await fetch('/api/opcode-names', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ locale, version, names })
  })
  const data = await res.json()
  return data.success
}
