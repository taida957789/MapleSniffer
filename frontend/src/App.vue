<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import {
  getStatus as bridgeGetStatus,
  getInterfaces as bridgeGetInterfaces,
  getPackets as bridgeGetPackets,
  startCapture as bridgeStartCapture,
  stopCapture as bridgeStopCapture,
  getScript,
  getSessions as bridgeGetSessions,
  getOpcodeNames as bridgeGetOpcodeNames,
  saveOpcodeNames as bridgeSaveOpcodeNames,
  decryptOpcodes as bridgeDecryptOpcodes,
  type NetworkInterface,
  type PacketInfo,
  type Status,
  type SessionMeta,
  type OpcodeNameMap
} from './bridge'
import { executeScript, type ParseResult } from './script-engine'
import type { ParsedField } from './packet-reader'
import TreeView from './components/TreeView.vue'
import ScriptEditor from './components/ScriptEditor.vue'
import OpcodeImporter from './components/OpcodeImporter.vue'
import ByteInspector from './components/ByteInspector.vue'

const interfaces = ref<NetworkInterface[]>([])
const selectedInterface = ref('')
const portMin = ref(8484)
const portMax = ref(9999)
const status = ref<Status>({ capturing: false, packetCount: 0, interface: '', filter: '' })
const packets = ref<PacketInfo[]>([])
const error = ref('')
const successMsg = ref('')
const activeTab = ref<'all' | 'in' | 'out'>('all')
const sortOrder = ref<'desc' | 'asc'>('desc')
const opcodeFilter = ref('')
const contentSearch = ref('')
const expandedPackets = ref<Set<number>>(new Set())
let pollTimer: ReturnType<typeof setInterval> | null = null

// Multi-session state
const sessions = ref<SessionMeta[]>([])
const activeSessionId = ref<number | null>(null)

// Hex highlight state
const highlightRange = ref<{ offset: number; length: number } | null>(null)

// User byte selection state (for byte inspector)
const userSelection = ref<{ start: number; end: number } | null>(null)
const inspectorPos = ref<{ x: number; y: number }>({ x: 0, y: 0 })
const dragAnchor = ref<number | null>(null)

// Script system state
const selectedPacket = ref<PacketInfo | null>(null)
const scriptCache = ref<Map<string, string | null>>(new Map())
const parseResult = ref<ParseResult | null>(null)
const editorVisible = ref(false)

// Opcode names state
const opcodeNamesCache = ref<Map<string, OpcodeNameMap>>(new Map())
const importerVisible = ref(false)
const opcodeNameInput = ref('')

// Context menu state
const contextMenu = ref<{ x: number; y: number; pkt: PacketInfo } | null>(null)

// Settings state
const settingsVisible = ref(false)
const desKeyInput = ref(localStorage.getItem('maple_des_key') || 'BrN=r54jQp2@yP6G')

function saveDesKey() {
  localStorage.setItem('maple_des_key', desKeyInput.value)
}

function formatOpcode(raw: number): string {
  return '0x' + raw.toString(16).toUpperCase().padStart(4, '0')
}

function selectPacket(pkt: PacketInfo) {
  if (selectedPacket.value?.index === pkt.index) {
    selectedPacket.value = null
    parseResult.value = null
  } else {
    selectedPacket.value = pkt
  }
}

function getSessionForPacket(pkt: PacketInfo): SessionMeta | undefined {
  return sessions.value.find(s => s.id === pkt.sessionId)
}

// --- Context menu ---

function onPacketContextMenu(pkt: PacketInfo, event: MouseEvent) {
  event.preventDefault()
  contextMenu.value = { x: event.clientX, y: event.clientY, pkt }
}

function closeContextMenu() {
  contextMenu.value = null
}

async function decryptOpcodeEncryption() {
  if (!contextMenu.value) return
  const pkt = contextMenu.value.pkt
  closeContextMenu()

  if (pkt.isHandshake || !pkt.hexDump) {
    error.value = 'This packet has no payload to decrypt'
    return
  }

  try {
    const mapping = await bridgeDecryptOpcodes(pkt.hexDump, desKeyInput.value)
    const entries = Object.entries(mapping)
    if (entries.length === 0) {
      error.value = 'Failed to decrypt opcode encryption: invalid format or no opcodes found'
      return
    }

    // Apply mapping to all outbound packets in the same session
    let remapped = 0
    for (const p of packets.value) {
      if (p.sessionId !== pkt.sessionId || !p.outbound || p.isHandshake) continue
      const realOp = mapping[String(p.opcodeRaw)]
      if (realOp !== undefined) {
        p.encryptedOpcodeRaw = p.opcodeRaw
        p.opcodeRaw = realOp
        p.opcode = formatOpcode(realOp)
        remapped++
      }
    }

    error.value = ''
    successMsg.value = `Opcode encryption applied: ${entries.length} mappings, ${remapped} packets remapped`
    setTimeout(() => { successMsg.value = '' }, 3000)
  } catch (e: any) {
    error.value = 'Decrypt failed: ' + e.message
  }
}

// Close context menu on click anywhere
function onDocumentClick(event: MouseEvent) {
  if (contextMenu.value) closeContextMenu()
  const target = event.target as HTMLElement
  if (!target.closest('.hex-interactive') && !target.closest('.inspector-popup')) {
    userSelection.value = null
  }
}

// --- Opcode names ---

function opcodeNamesCacheKey(locale: number, version: number): string {
  return `${locale}_${version}`
}

async function loadOpcodeNames(locale: number, version: number) {
  const key = opcodeNamesCacheKey(locale, version)
  if (opcodeNamesCache.value.has(key)) return
  try {
    const names = await bridgeGetOpcodeNames(locale, version)
    if (!names.send) names.send = {}
    if (!names.recv) names.recv = {}
    opcodeNamesCache.value.set(key, names)
  } catch {
    opcodeNamesCache.value.set(key, { send: {}, recv: {} })
  }
}

function getOpcodeName(pkt: PacketInfo): string | null {
  if (pkt.isHandshake) return null
  const session = getSessionForPacket(pkt)
  if (!session) return null
  const key = opcodeNamesCacheKey(session.locale, session.version)
  const names = opcodeNamesCache.value.get(key)
  if (!names) return null
  const dir = pkt.outbound ? 'send' : 'recv'
  return names[dir]?.[String(pkt.opcodeRaw)] ?? null
}

function displayOpcode(pkt: PacketInfo): string {
  if (pkt.isHandshake) return 'Handshake'
  const name = getOpcodeName(pkt)
  const base = name ? `${name}(${pkt.opcode})` : pkt.opcode
  if (pkt.encryptedOpcodeRaw !== undefined) {
    return `${base} [enc:${formatOpcode(pkt.encryptedOpcodeRaw)}]`
  }
  return base
}

const currentOpcodeName = computed(() => {
  if (!selectedPacket.value || selectedPacket.value.isHandshake) return ''
  return getOpcodeName(selectedPacket.value) ?? ''
})

watch(selectedPacket, () => {
  opcodeNameInput.value = currentOpcodeName.value
})

async function saveOpcodeName() {
  if (!selectedPacket.value || selectedPacket.value.isHandshake) return
  const session = selectedPacketSession.value
  if (!session) return

  const key = opcodeNamesCacheKey(session.locale, session.version)
  let names = opcodeNamesCache.value.get(key)
  if (!names) names = { send: {}, recv: {} }

  const dir = selectedPacket.value.outbound ? 'send' : 'recv'
  const opcodeKey = String(selectedPacket.value.opcodeRaw)
  const trimmed = opcodeNameInput.value.trim()

  if (trimmed) {
    names[dir][opcodeKey] = trimmed
  } else {
    delete names[dir][opcodeKey]
  }

  // Update cache reactively
  opcodeNamesCache.value.set(key, { send: { ...names.send }, recv: { ...names.recv } })
  // Trigger reactivity
  opcodeNamesCache.value = new Map(opcodeNamesCache.value)

  await bridgeSaveOpcodeNames(session.locale, session.version, names)
}

async function onOpcodesImported() {
  // Reload opcode names for the active session
  const s = activeImporterSession.value
  if (s) {
    const key = opcodeNamesCacheKey(s.locale, s.version)
    opcodeNamesCache.value.delete(key)
    await loadOpcodeNames(s.locale, s.version)
    // Trigger reactivity
    opcodeNamesCache.value = new Map(opcodeNamesCache.value)
  }
}

// --- Script system ---

function scriptCacheKey(pkt: PacketInfo): string {
  const session = getSessionForPacket(pkt)
  const locale = session?.locale ?? 0
  const version = session?.version ?? 0
  return `${locale}_${version}_${pkt.outbound ? 'send' : 'recv'}_${pkt.opcodeRaw}`
}

watch(selectedPacket, async (pkt) => {
  parseResult.value = null
  highlightRange.value = null
  userSelection.value = null
  if (!pkt || pkt.isHandshake) return

  const session = getSessionForPacket(pkt)
  if (!session) return

  const key = scriptCacheKey(pkt)
  let code: string | null | undefined = scriptCache.value.get(key)
  if (code === undefined) {
    try {
      const direction = pkt.outbound ? 'send' : 'recv'
      code = await getScript(direction, pkt.opcodeRaw, session.locale, session.version)
      scriptCache.value.set(key, code || null)
    } catch {
      scriptCache.value.set(key, null)
      code = null
    }
  }

  if (code) {
    parseResult.value = executeScript(pkt.hexDump, code)
  }
})

function openEditor() {
  if (selectedPacket.value && !selectedPacket.value.isHandshake) {
    editorVisible.value = true
  }
}

function onScriptSaved() {
  editorVisible.value = false
  if (selectedPacket.value) {
    const key = scriptCacheKey(selectedPacket.value)
    scriptCache.value.delete(key)
    const pkt = selectedPacket.value
    selectedPacket.value = null
    setTimeout(() => { selectedPacket.value = pkt }, 0)
  }
}

// --- Export / Import ---

function downloadJson(data: any, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function exportSession() {
  if (activeSessionId.value === null) return
  const session = sessions.value.find(s => s.id === activeSessionId.value)
  if (!session) return

  const sessionPackets = packets.value.filter(p => p.sessionId === activeSessionId.value)
  const key = opcodeNamesCacheKey(session.locale, session.version)
  const names = opcodeNamesCache.value.get(key) ?? { send: {}, recv: {} }

  const time = session.timestamp
    ? new Date(session.timestamp * 1000).toTimeString().slice(0, 8).replace(/:/g, '')
    : 'unknown'
  const filename = `session_v${session.version}_${session.serverPort}_${time}.json`

  downloadJson({ session, opcodeNames: names, packets: sessionPackets }, filename)
}

const fileInput = ref<HTMLInputElement | null>(null)

function triggerImport() {
  fileInput.value?.click()
}

async function importSession(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  input.value = ''

  try {
    const text = await file.text()
    const data = JSON.parse(text)

    if (!data.session || !Array.isArray(data.packets)) {
      error.value = 'Invalid session file format'
      return
    }

    // Assign new session ID
    const maxId = sessions.value.length > 0
      ? Math.max(...sessions.value.map(s => s.id))
      : 0
    const newId = maxId + 1

    const imported: SessionMeta = {
      id: newId,
      locale: data.session.locale ?? 0,
      version: data.session.version ?? 0,
      subVersion: data.session.subVersion ?? '',
      serverPort: data.session.serverPort ?? 0,
      timestamp: data.session.timestamp ?? 0,
      dead: false
    }

    sessions.value.push(imported)

    // Remap packets to new session ID
    const importedPackets: PacketInfo[] = data.packets.map((p: any) => ({
      ...p,
      sessionId: newId
    }))
    packets.value.push(...importedPackets)

    // Load opcode names
    if (data.opcodeNames) {
      const key = opcodeNamesCacheKey(imported.locale, imported.version)
      const names = data.opcodeNames as OpcodeNameMap
      if (!names.send) names.send = {}
      if (!names.recv) names.recv = {}
      opcodeNamesCache.value.set(key, names)
      opcodeNamesCache.value = new Map(opcodeNamesCache.value)
    }

    // Switch to imported session
    activeSessionId.value = newId
    currentPage.value = 1
    error.value = ''
  } catch (e: any) {
    error.value = 'Failed to import session: ' + e.message
  }
}

// --- Hex highlight ---

function onFieldSelect(offset: number, length: number) {
  highlightRange.value = { offset, length }
  userSelection.value = null
}

const hexBytes = computed((): string[] => {
  if (!selectedPacket.value) return []
  return selectedPacket.value.hexDump.split(/\s+/).filter(s => /^[0-9a-fA-F]{2}$/i.test(s))
})

const hexRows = computed(() => {
  const bytes = hexBytes.value
  const rows: string[][] = []
  for (let i = 0; i < bytes.length; i += 16) {
    rows.push(bytes.slice(i, i + 16))
  }
  return rows
})

function isHighlighted(byteIndex: number): boolean {
  if (!highlightRange.value) return false
  const { offset, length } = highlightRange.value
  return byteIndex >= offset && byteIndex < offset + length
}

function isUserSelected(byteIndex: number): boolean {
  if (!userSelection.value) return false
  return byteIndex >= userSelection.value.start && byteIndex <= userSelection.value.end
}

function onByteMouseDown(byteIndex: number, event: MouseEvent) {
  if (event.button !== 0) return
  if (event.shiftKey && userSelection.value) {
    userSelection.value = {
      start: Math.min(userSelection.value.start, byteIndex),
      end: Math.max(userSelection.value.start, byteIndex)
    }
  } else {
    dragAnchor.value = byteIndex
    userSelection.value = { start: byteIndex, end: byteIndex }
  }
  inspectorPos.value = { x: event.clientX, y: event.clientY }
  highlightRange.value = null
}

function onByteMouseMove(byteIndex: number, event: MouseEvent) {
  if (dragAnchor.value === null) return
  const anchor = dragAnchor.value
  userSelection.value = {
    start: Math.min(anchor, byteIndex),
    end: Math.max(anchor, byteIndex)
  }
  inspectorPos.value = { x: event.clientX, y: event.clientY }
}

function onDocumentMouseUp() {
  dragAnchor.value = null
}

const selectedBytes = computed((): number[] => {
  if (!userSelection.value || hexBytes.value.length === 0) return []
  const { start, end } = userSelection.value
  return hexBytes.value.slice(start, end + 1).map(h => parseInt(h, 16))
})

// --- UI helpers ---

function toggleHex(index: number) {
  const s = expandedPackets.value
  if (s.has(index)) s.delete(index)
  else s.add(index)
}

function isExpanded(index: number): boolean {
  return expandedPackets.value.has(index)
}

const HEX_PREVIEW_LINES = 3

function previewHex(hex: string): string {
  const lines = hex.split('\n')
  if (lines.length <= HEX_PREVIEW_LINES) return hex
  return lines.slice(0, HEX_PREVIEW_LINES).join('\n')
}

function needsTruncation(hex: string): boolean {
  return hex.split('\n').length > HEX_PREVIEW_LINES
}

function matchesContent(pkt: PacketInfo, query: string): boolean {
  if (!query) return true
  const q = query.trim()
  const hexNorm = q.replace(/\s+/g, '').toLowerCase()
  if (/^[0-9a-f]+$/.test(hexNorm) && hexNorm.length >= 2 && hexNorm.length % 2 === 0) {
    const hexSpaced = hexNorm.match(/.{2}/g)!.join(' ')
    if (pkt.hexDump.toLowerCase().includes(hexSpaced)) return true
  }
  const asciiHex = Array.from(q).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ')
  if (pkt.hexDump.toLowerCase().includes(asciiHex)) return true
  return false
}

const filteredPackets = computed(() => {
  let list = packets.value

  if (activeSessionId.value !== null) {
    list = list.filter(p => p.sessionId === activeSessionId.value)
  }

  if (activeTab.value === 'in') list = list.filter(p => !p.outbound)
  else if (activeTab.value === 'out') list = list.filter(p => p.outbound)

  if (opcodeFilter.value) {
    const q = opcodeFilter.value.trim().toLowerCase()
    list = list.filter(p => {
      // Match against hex opcode
      if (p.opcode.toLowerCase().includes(q)) return true
      // Match against opcode name
      const name = getOpcodeName(p)
      if (name && name.toLowerCase().includes(q)) return true
      return false
    })
  }
  if (contentSearch.value) {
    list = list.filter(p => matchesContent(p, contentSearch.value))
  }
  return sortOrder.value === 'desc' ? [...list].reverse() : list
})

function switchTab(tab: 'all' | 'in' | 'out') {
  activeTab.value = tab
  currentPage.value = 1
}

function switchSession(id: number | null) {
  activeSessionId.value = id
  currentPage.value = 1
}

const inCount = computed(() => {
  let list = packets.value
  if (activeSessionId.value !== null) {
    list = list.filter(p => p.sessionId === activeSessionId.value)
  }
  return list.filter(p => !p.outbound).length
})

const outCount = computed(() => {
  let list = packets.value
  if (activeSessionId.value !== null) {
    list = list.filter(p => p.sessionId === activeSessionId.value)
  }
  return list.filter(p => p.outbound).length
})

const sessionPacketCount = computed(() => {
  if (activeSessionId.value === null) return packets.value.length
  return packets.value.filter(p => p.sessionId === activeSessionId.value).length
})

const PAGE_SIZE = 50
const currentPage = ref(1)

const totalPages = computed(() => Math.max(1, Math.ceil(filteredPackets.value.length / PAGE_SIZE)))
const pagedPackets = computed(() => {
  const start = (currentPage.value - 1) * PAGE_SIZE
  return filteredPackets.value.slice(start, start + PAGE_SIZE)
})

function buildFilter(): string {
  return `tcp portrange ${portMin.value}-${portMax.value}`
}

async function loadInterfaces() {
  try {
    interfaces.value = await bridgeGetInterfaces()
    const saved = localStorage.getItem('maple_interface')
    if (saved && interfaces.value.some(i => i.name === saved)) {
      selectedInterface.value = saved
    } else if (interfaces.value.length > 0 && !selectedInterface.value) {
      selectedInterface.value = interfaces.value[0].name
    }
    error.value = ''
  } catch (e: any) {
    error.value = 'Failed to load interfaces: ' + e.message
  }
}

async function loadStatus() {
  try {
    status.value = await bridgeGetStatus()
    if (status.value.capturing && status.value.interface) {
      selectedInterface.value = status.value.interface
    }
  } catch {}
}

async function loadSessions() {
  try {
    const newSessions = await bridgeGetSessions()
    if (newSessions.length > sessions.value.length) {
      const latest = newSessions[newSessions.length - 1]
      activeSessionId.value = latest.id
      // Load opcode names for new session
      loadOpcodeNames(latest.locale, latest.version)
    }
    sessions.value = newSessions
  } catch {}
}

let serverPacketCount = 0

async function loadPackets() {
  try {
    const newPackets = await bridgeGetPackets(serverPacketCount)
    if (newPackets.length > 0) {
      serverPacketCount += newPackets.length
      packets.value.push(...newPackets)
      if (packets.value.length > 2000) {
        packets.value = packets.value.slice(-2000)
      }
    }
  } catch {}
}

async function startCapture() {
  if (!selectedInterface.value) {
    error.value = 'Please select an interface'
    return
  }
  try {
    packets.value = []
    serverPacketCount = 0
    selectedPacket.value = null
    parseResult.value = null
    scriptCache.value.clear()
    opcodeNamesCache.value.clear()
    sessions.value = []
    activeSessionId.value = null
    await bridgeStartCapture(selectedInterface.value, buildFilter())
    localStorage.setItem('maple_interface', selectedInterface.value)
    error.value = ''
    await loadStatus()
  } catch (e: any) {
    error.value = 'Failed to start capture: ' + e.message
  }
}

async function stopCapture() {
  try {
    await bridgeStopCapture()
    error.value = ''
    await loadStatus()
  } catch (e: any) {
    error.value = 'Failed to stop capture: ' + e.message
  }
}

function formatTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString('zh-TW', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

function sessionLabel(s: SessionMeta): string {
  const time = s.timestamp ? formatTimestamp(s.timestamp) + ' ' : ''
  return `${time}v${s.version} :${s.serverPort}`
}

const selectedPacketSession = computed(() => {
  if (!selectedPacket.value) return null
  return getSessionForPacket(selectedPacket.value) ?? null
})

const hasSession = computed(() => sessions.value.length > 0)

// Session used for the importer (the active one)
const activeImporterSession = computed(() => {
  if (activeSessionId.value === null) return sessions.value[0] ?? null
  return sessions.value.find(s => s.id === activeSessionId.value) ?? null
})

const handshakeFields = computed((): ParsedField[] => {
  const pkt = selectedPacket.value
  if (!pkt || !pkt.isHandshake) return []
  return [
    { name: 'version', type: 'short', value: pkt.version ?? 0, offset: 2, length: 2 },
    { name: 'subVersion', type: 'string', value: pkt.subVersion ?? '', offset: 6, length: (pkt.subVersion ?? '').length },
    { name: 'locale', type: 'byte', value: pkt.locale ?? 0, offset: 0, length: 1 },
  ]
})

onMounted(async () => {
  document.addEventListener('click', onDocumentClick)
  document.addEventListener('mouseup', onDocumentMouseUp)
  await loadInterfaces()
  await loadStatus()
  if (status.value.capturing) {
    await loadPackets()
    await loadSessions()
    // Load opcode names for all existing sessions
    for (const s of sessions.value) {
      loadOpcodeNames(s.locale, s.version)
    }
  }
  pollTimer = setInterval(() => {
    loadStatus()
    if (status.value.capturing) {
      loadPackets()
      loadSessions()
    }
  }, 1000)
})

onUnmounted(() => {
  document.removeEventListener('click', onDocumentClick)
  document.removeEventListener('mouseup', onDocumentMouseUp)
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<template>
  <div class="app">
    <header>
      <h1>MapleSniffer</h1>
      <span class="status-badge" :class="{ active: status.capturing }">
        {{ status.capturing ? 'Capturing' : 'Idle' }}
      </span>
      <span v-if="hasSession && activeSessionId !== null" class="session-badge">
        {{ sessionLabel(sessions.find(s => s.id === activeSessionId)!) }}
        locale={{ sessions.find(s => s.id === activeSessionId)!.locale }}
      </span>
      <button class="btn-settings" @click="settingsVisible = !settingsVisible" :class="{ active: settingsVisible }">
        Settings
      </button>
    </header>

    <!-- Settings Panel -->
    <section v-if="settingsVisible" class="settings-panel">
      <div class="settings-row">
        <label class="settings-label">3DES Key (16 chars)</label>
        <input
          v-model="desKeyInput"
          class="settings-input"
          maxlength="16"
          placeholder="BrN=r54jQp2@yP6G"
          @change="saveDesKey"
        />
        <span class="settings-hint" :class="{ 'settings-warn': desKeyInput.length !== 16 }">
          {{ desKeyInput.length }}/16
        </span>
      </div>
    </section>

    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="successMsg" class="success">{{ successMsg }}</div>

    <section class="controls">
      <div class="field">
        <label>Network Interface</label>
        <select v-model="selectedInterface" :disabled="status.capturing">
          <option v-for="iface in interfaces" :key="iface.name" :value="iface.name">
            {{ iface.friendlyName || iface.description || iface.name }}
          </option>
        </select>
      </div>

      <div class="field field-port">
        <label>TCP Port Range</label>
        <div class="port-range">
          <input
            v-model.number="portMin"
            type="number"
            min="1"
            max="65535"
            :disabled="status.capturing"
          />
          <span class="port-sep">~</span>
          <input
            v-model.number="portMax"
            type="number"
            min="1"
            max="65535"
            :disabled="status.capturing"
          />
        </div>
      </div>

      <div class="actions">
        <button v-if="!status.capturing" @click="startCapture" class="btn-start">
          Start Capture
        </button>
        <button v-else @click="stopCapture" class="btn-stop">
          Stop Capture
        </button>
      </div>
    </section>

    <!-- Session Tabs -->
    <section v-if="sessions.length > 0" class="session-tabs">
      <button
        class="session-tab"
        :class="{ active: activeSessionId === null }"
        @click="switchSession(null)"
      >All Sessions</button>
      <button
        v-for="s in sessions"
        :key="s.id"
        class="session-tab"
        :class="{ active: activeSessionId === s.id, dead: s.dead }"
        @click="switchSession(s.id)"
      >{{ sessionLabel(s) }}<span v-if="s.dead" class="dead-badge">DEAD</span></button>
      <button
        v-if="activeSessionId !== null"
        class="btn-session-action"
        @click="exportSession"
      >Export</button>
      <button
        class="btn-session-action"
        @click="triggerImport"
      >Import</button>
      <input
        ref="fileInput"
        type="file"
        accept=".json"
        style="display: none"
        @change="importSession"
      />
      <button
        v-if="activeImporterSession"
        class="btn-import-opcodes"
        @click="importerVisible = true"
      >Manage Opcodes</button>
    </section>

    <!-- Packets Page -->
    <section class="packets">
      <div class="packet-toolbar">
        <div class="tabs">
          <button
            class="tab"
            :class="{ active: activeTab === 'all' }"
            @click="switchTab('all')"
          >All ({{ sessionPacketCount }})</button>
          <button
            class="tab tab-in"
            :class="{ active: activeTab === 'in' }"
            @click="switchTab('in')"
          >IN ({{ inCount }})</button>
          <button
            class="tab tab-out"
            :class="{ active: activeTab === 'out' }"
            @click="switchTab('out')"
          >OUT ({{ outCount }})</button>
        </div>
        <select v-model="sortOrder" class="sort-select">
          <option value="desc">Newest First</option>
          <option value="asc">Oldest First</option>
        </select>
      </div>
      <div class="filter-bar">
        <input
          v-model="opcodeFilter"
          type="text"
          class="filter-input"
          placeholder="Filter opcode / name (e.g. 0x00B5, LP_SetField)"
        />
        <input
          v-model="contentSearch"
          type="text"
          class="filter-input filter-content"
          placeholder="Search content (hex: AB CD / ascii: hello)"
        />
      </div>
      <div class="packet-list">
        <div v-if="filteredPackets.length === 0" class="empty">
          No packets captured yet.
        </div>
        <div
          v-for="pkt in pagedPackets"
          :key="pkt.index"
          class="packet-item"
          :class="{ handshake: pkt.isHandshake, selected: selectedPacket?.index === pkt.index }"
          @click="selectPacket(pkt)"
          @contextmenu="onPacketContextMenu(pkt, $event)"
        >
          <div class="packet-header">
            <span class="pkt-index">#{{ pkt.index }}</span>
            <span class="pkt-time">{{ formatTimestamp(pkt.timestamp) }}</span>
            <span class="pkt-opcode" :class="{ 'opcode-hs': pkt.isHandshake, 'opcode-named': !!getOpcodeName(pkt) }">
              {{ displayOpcode(pkt) }}
            </span>
            <span class="pkt-dir" :class="{ outbound: pkt.outbound, inbound: !pkt.outbound }">
              {{ pkt.outbound ? '→ OUT' : '← IN' }}
            </span>
            <span class="pkt-len">{{ pkt.length }} B</span>
            <span v-if="pkt.isHandshake" class="pkt-hs-info">
              v{{ pkt.version }}.{{ pkt.subVersion }} locale={{ pkt.locale }}
            </span>
          </div>
        </div>
      </div>
      <div v-if="totalPages > 1" class="pagination">
        <button class="page-btn" :disabled="currentPage <= 1" @click="currentPage = 1">&laquo;</button>
        <button class="page-btn" :disabled="currentPage <= 1" @click="currentPage--">&lsaquo;</button>
        <span class="page-info">{{ currentPage }} / {{ totalPages }}</span>
        <button class="page-btn" :disabled="currentPage >= totalPages" @click="currentPage++">&rsaquo;</button>
        <button class="page-btn" :disabled="currentPage >= totalPages" @click="currentPage = totalPages">&raquo;</button>
      </div>
    </section>

    <!-- Detail Panel -->
    <section v-if="selectedPacket" class="detail-panel">
      <div class="detail-header">
        <span class="detail-title">
          #{{ selectedPacket.index }} &mdash;
          {{ displayOpcode(selectedPacket) }}
          ({{ selectedPacket.outbound ? 'OUT' : 'IN' }})
          &mdash; {{ selectedPacket.length }} B
        </span>
        <button class="btn-close-detail" @click="selectedPacket = null; parseResult = null">&times;</button>
      </div>
      <!-- Opcode name editor row -->
      <div v-if="selectedPacketSession && !selectedPacket.isHandshake" class="opcode-name-row">
        <label class="opcode-name-label">Name</label>
        <input
          v-model="opcodeNameInput"
          class="opcode-name-input"
          placeholder="e.g. LP_SetField"
          @keyup.enter="saveOpcodeName"
        />
        <button
          v-if="opcodeNameInput.trim() !== currentOpcodeName"
          class="btn-save-name"
          @click="saveOpcodeName"
        >Save</button>
      </div>
      <div class="detail-body">
        <div class="detail-hex">
          <div class="detail-section-title">Hex Dump</div>
          <div class="pkt-hex hex-interactive">
            <div v-for="(row, rowIdx) in hexRows" :key="rowIdx" class="hex-row">
              <span class="hex-addr">{{ (rowIdx * 16).toString(16).padStart(4, '0').toUpperCase() }}</span>
              <span
                v-for="(byte, colIdx) in row"
                :key="colIdx"
                class="hex-byte"
                :class="{
                  'hex-hl': isHighlighted(rowIdx * 16 + colIdx),
                  'hex-sel': isUserSelected(rowIdx * 16 + colIdx)
                }"
                @mousedown.stop.prevent="onByteMouseDown(rowIdx * 16 + colIdx, $event)"
                @mousemove="onByteMouseMove(rowIdx * 16 + colIdx, $event)"
              >{{ byte }}</span>
            </div>
          </div>
        </div>
        <div class="detail-parsed">
          <div class="detail-section-header">
            <span class="detail-section-title">Parsed Fields</span>
            <button
              v-if="selectedPacketSession && !selectedPacket.isHandshake"
              class="btn-edit-script"
              @click="openEditor"
            >
              {{ parseResult ? 'Edit Script' : 'Create Script' }}
            </button>
          </div>
          <div v-if="selectedPacket.isHandshake" class="parsed-content">
            <TreeView
              :fields="handshakeFields"
              :selected-offset="highlightRange?.offset ?? -1"
              :selected-length="highlightRange?.length ?? 0"
              @select="onFieldSelect"
            />
          </div>
          <div v-else-if="!selectedPacketSession" class="parsed-placeholder">
            Waiting for handshake...
          </div>
          <div v-else-if="!parseResult" class="parsed-placeholder">
            No script for this opcode
          </div>
          <div v-else class="parsed-content">
            <TreeView
              :fields="parseResult.fields"
              :selected-offset="highlightRange?.offset ?? -1"
              :selected-length="highlightRange?.length ?? 0"
              @select="onFieldSelect"
            />
            <div v-if="!parseResult.success" class="parse-error">
              Error: {{ parseResult.error }}
            </div>
            <div v-if="parseResult.fields.length === 0 && parseResult.success" class="parsed-placeholder">
              Script produced no output
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Script Editor Modal -->
    <ScriptEditor
      v-if="selectedPacket && !selectedPacket.isHandshake && selectedPacketSession"
      :visible="editorVisible"
      :direction="selectedPacket.outbound ? 'send' : 'recv'"
      :opcode="selectedPacket.opcodeRaw"
      :locale="selectedPacketSession.locale"
      :version="selectedPacketSession.version"
      @close="editorVisible = false"
      @saved="onScriptSaved"
    />

    <!-- Opcode Importer Modal -->
    <OpcodeImporter
      v-if="activeImporterSession"
      :visible="importerVisible"
      :locale="activeImporterSession.locale"
      :version="activeImporterSession.version"
      @close="importerVisible = false"
      @imported="onOpcodesImported"
    />

    <!-- Context Menu -->
    <Teleport to="body">
      <div
        v-if="contextMenu"
        class="context-menu"
        :style="{ left: contextMenu.x + 'px', top: contextMenu.y + 'px' }"
        @click.stop
      >
        <button class="ctx-item" @click="decryptOpcodeEncryption">
          Decrypt Opcode Encryption
        </button>
      </div>
    </Teleport>

    <!-- Byte Inspector Popup -->
    <Teleport to="body">
      <div
        v-if="userSelection && selectedBytes.length > 0"
        class="inspector-popup"
        :style="{ left: inspectorPos.x + 'px', top: inspectorPos.y + 'px' }"
        @click.stop
      >
        <ByteInspector :bytes="selectedBytes" :visible="true" />
      </div>
    </Teleport>
  </div>
</template>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #1a1a2e;
  color: #e0e0e0;
}

.app {
  padding: 20px;
}

header {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 24px;
}

header h1 {
  font-size: 24px;
  color: #60d394;
}

.status-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 13px;
  font-weight: 600;
  background: #333;
  color: #888;
}

.status-badge.active {
  background: #1b4332;
  color: #60d394;
}

.session-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
  background: #2a2a1e;
  color: #f0c040;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
}

.error {
  background: #4a1525;
  color: #ff6b6b;
  padding: 10px 16px;
  border-radius: 8px;
  margin-bottom: 16px;
  font-size: 14px;
}

.success {
  background: #1b4332;
  color: #60d394;
  padding: 10px 16px;
  border-radius: 8px;
  margin-bottom: 16px;
  font-size: 14px;
}

.controls {
  background: #16213e;
  padding: 20px;
  border-radius: 12px;
  margin-bottom: 24px;
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  align-items: flex-end;
}

.field {
  flex: 1;
  min-width: 200px;
}

.field label {
  display: block;
  font-size: 13px;
  color: #888;
  margin-bottom: 6px;
}

.field select,
.field input {
  width: 100%;
  padding: 8px 12px;
  background: #0f3460;
  border: 1px solid #1a4a7a;
  border-radius: 6px;
  color: #e0e0e0;
  font-size: 14px;
  outline: none;
}

.field select:focus,
.field input:focus {
  border-color: #60d394;
}

.field-port {
  min-width: 180px;
  flex: 0 1 auto;
}

.port-range {
  display: flex;
  align-items: center;
  gap: 6px;
}

.port-range input {
  width: 90px;
  text-align: center;
}

.port-sep {
  color: #888;
  font-size: 16px;
}

.actions {
  display: flex;
  gap: 8px;
}

button {
  padding: 8px 20px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s;
}

button:hover {
  opacity: 0.85;
}

.btn-start {
  background: #60d394;
  color: #1a1a2e;
}

.btn-stop {
  background: #ff6b6b;
  color: #fff;
}

/* Session Tabs */
.session-tabs {
  display: flex;
  gap: 4px;
  margin-bottom: 16px;
  flex-wrap: wrap;
  align-items: center;
}

.session-tab {
  padding: 6px 14px;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 600;
  background: #16213e;
  color: #888;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.15s;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
}

.session-tab:hover {
  color: #bbb;
  opacity: 1;
}

.session-tab.active {
  background: #2a2a1e;
  color: #f0c040;
  border-color: #5a4a1a;
}

.session-tab.dead {
  opacity: 0.5;
}

.dead-badge {
  margin-left: 6px;
  font-size: 9px;
  padding: 1px 4px;
  border-radius: 3px;
  background: #ff4444;
  color: #fff;
  vertical-align: middle;
}

.btn-session-action {
  padding: 5px 12px;
  font-size: 11px;
  font-weight: 600;
  background: #0f3460;
  color: #60d394;
  border: 1px solid #1a4a7a;
  border-radius: 6px;
  cursor: pointer;
  margin-left: 4px;
}

.btn-session-action:hover {
  background: #1a4a7a;
  color: #e0e0e0;
  opacity: 1;
}

.btn-import-opcodes {
  padding: 5px 12px;
  font-size: 11px;
  font-weight: 600;
  background: #0f3460;
  color: #7ab8ff;
  border: 1px solid #1a4a7a;
  border-radius: 6px;
  cursor: pointer;
  margin-left: 8px;
}

.btn-import-opcodes:hover {
  background: #1a4a7a;
  color: #e0e0e0;
  opacity: 1;
}

.packet-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}

.tabs {
  display: flex;
  gap: 4px;
}

.sort-select {
  padding: 6px 10px;
  background: #0f3460;
  border: 1px solid #1a4a7a;
  border-radius: 6px;
  color: #e0e0e0;
  font-size: 13px;
  outline: none;
  cursor: pointer;
}

.sort-select:focus {
  border-color: #60d394;
}

.tab {
  padding: 6px 16px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 600;
  background: #16213e;
  color: #888;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.15s;
}

.tab:hover {
  color: #bbb;
  opacity: 1;
}

.tab.active {
  background: #0f3460;
  color: #e0e0e0;
  border-color: #1a4a7a;
}

.tab-in.active {
  color: #c77dff;
  border-color: #6a3a8a;
}

.tab-out.active {
  color: #7ab8ff;
  border-color: #2a4a6a;
}

.filter-bar {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.filter-input {
  padding: 6px 10px;
  background: #0f3460;
  border: 1px solid #1a4a7a;
  border-radius: 6px;
  color: #e0e0e0;
  font-size: 13px;
  outline: none;
  width: 240px;
}

.filter-input:focus {
  border-color: #60d394;
}

.filter-content {
  flex: 1;
}

.packet-list {
  max-height: 400px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.empty {
  text-align: center;
  color: #555;
  padding: 40px 0;
}

.packet-item {
  background: #16213e;
  border-radius: 8px;
  padding: 10px 16px;
  cursor: pointer;
  border: 1px solid transparent;
  transition: border-color 0.15s;
}

.packet-item:hover {
  border-color: #1a4a7a;
}

.packet-item.selected {
  border-color: #60d394;
  background: #1a2a4e;
}

.packet-item.handshake {
  border-left: 3px solid #f0c040;
}

.packet-header {
  display: flex;
  gap: 12px;
  font-size: 13px;
  align-items: center;
}

.pkt-index {
  color: #60d394;
  font-weight: 600;
}

.pkt-time {
  color: #888;
}

.pkt-opcode {
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  font-weight: 700;
  color: #ffd166;
}

.pkt-opcode.opcode-hs {
  color: #f0c040;
}

.pkt-opcode.opcode-named {
  color: #60d394;
}

.pkt-len {
  color: #aaa;
}

.pkt-dir {
  padding: 1px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
}

.pkt-dir.outbound {
  background: #2a4a6a;
  color: #7ab8ff;
}

.pkt-dir.inbound {
  background: #3a2a4a;
  color: #c77dff;
}

.pkt-hs-info {
  color: #f0c040;
  font-size: 12px;
}

.pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 12px;
  padding: 8px 0;
}

.page-btn {
  padding: 4px 12px;
  font-size: 14px;
  background: #16213e;
  color: #aaa;
  border: 1px solid #1a4a7a;
  border-radius: 4px;
  cursor: pointer;
}

.page-btn:hover:not(:disabled) {
  background: #0f3460;
  color: #e0e0e0;
  opacity: 1;
}

.page-btn:disabled {
  opacity: 0.3;
  cursor: default;
}

.page-info {
  color: #888;
  font-size: 13px;
  min-width: 60px;
  text-align: center;
}

.pkt-hex {
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  font-size: 12px;
  color: #7ab8ff;
  background: #0f3460;
  padding: 8px 12px;
  border-radius: 6px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.hex-interactive {
  white-space: normal;
  word-break: normal;
  user-select: none;
}

.hex-row {
  display: flex;
  gap: 0;
  line-height: 1.7;
}

.hex-addr {
  color: #555;
  margin-right: 10px;
  user-select: none;
  flex-shrink: 0;
}

.hex-byte {
  padding: 0 2.5px;
  border-radius: 2px;
  transition: background 0.1s;
  cursor: pointer;
}

.hex-byte:hover {
  background: #1a4a7a;
}

.hex-byte.hex-hl {
  background: #e6a817;
  color: #1a1a2e;
}

.hex-byte.hex-sel {
  background: #1a8a8a;
  color: #e0f0f0;
}

/* Detail Panel */
.detail-panel {
  margin-top: 16px;
  background: #16213e;
  border-radius: 12px;
  overflow: hidden;
}

.detail-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 20px;
  background: #0f3460;
  border-bottom: 1px solid #1a4a7a;
}

.detail-title {
  font-size: 13px;
  font-weight: 600;
  color: #e0e0e0;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
}

.btn-close-detail {
  background: none;
  border: none;
  color: #888;
  font-size: 20px;
  cursor: pointer;
  padding: 0 4px;
  line-height: 1;
}

.btn-close-detail:hover {
  color: #e0e0e0;
  opacity: 1;
}

/* Opcode name editor row */
.opcode-name-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 20px;
  background: #0d2b50;
  border-bottom: 1px solid #1a4a7a;
}

.opcode-name-label {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #888;
  white-space: nowrap;
}

.opcode-name-input {
  flex: 1;
  padding: 4px 8px;
  background: #0f3460;
  border: 1px solid #1a4a7a;
  border-radius: 4px;
  color: #e0e0e0;
  font-size: 12px;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  outline: none;
}

.opcode-name-input:focus {
  border-color: #60d394;
}

.btn-save-name {
  padding: 3px 10px;
  font-size: 11px;
  font-weight: 600;
  background: #60d394;
  color: #1a1a2e;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.btn-save-name:hover {
  opacity: 0.85;
}

.detail-body {
  display: flex;
  gap: 0;
  min-height: 200px;
}

.detail-hex {
  flex: 1;
  padding: 12px 16px;
  border-right: 1px solid #1a4a7a;
  overflow: auto;
  max-height: 400px;
}

.detail-parsed {
  flex: 1;
  padding: 12px 16px;
  overflow: auto;
  max-height: 400px;
}

.detail-section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.detail-section-title {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #888;
  margin-bottom: 8px;
}

.detail-section-header .detail-section-title {
  margin-bottom: 0;
}

.btn-edit-script {
  padding: 3px 10px;
  font-size: 11px;
  font-weight: 600;
  background: #0f3460;
  color: #7ab8ff;
  border: 1px solid #1a4a7a;
  border-radius: 4px;
  cursor: pointer;
}

.btn-edit-script:hover {
  background: #1a4a7a;
  color: #e0e0e0;
  opacity: 1;
}

.parsed-placeholder {
  color: #555;
  font-size: 13px;
  padding: 20px 0;
  text-align: center;
}

.parsed-content {
  min-height: 50px;
}

.parse-error {
  margin-top: 8px;
  padding: 8px 12px;
  background: #4a1525;
  color: #ff6b6b;
  border-radius: 6px;
  font-size: 12px;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
}

/* Context Menu */
.context-menu {
  position: fixed;
  z-index: 9999;
  background: #1a2a4e;
  border: 1px solid #1a4a7a;
  border-radius: 8px;
  padding: 4px 0;
  min-width: 200px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5);
}

.ctx-item {
  display: block;
  width: 100%;
  text-align: left;
  padding: 8px 16px;
  background: none;
  border: none;
  border-radius: 0;
  color: #e0e0e0;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
}

.ctx-item:hover {
  background: #0f3460;
  opacity: 1;
}

/* Byte Inspector Popup */
.inspector-popup {
  position: fixed;
  z-index: 9998;
  transform: translate(12px, 12px);
  max-width: 420px;
  max-height: 80vh;
  overflow-y: auto;
}

/* Settings */
.btn-settings {
  margin-left: auto;
  padding: 4px 12px;
  font-size: 12px;
  font-weight: 600;
  background: #16213e;
  color: #888;
  border: 1px solid #1a4a7a;
  border-radius: 6px;
  cursor: pointer;
}

.btn-settings:hover {
  color: #e0e0e0;
  opacity: 1;
}

.btn-settings.active {
  background: #0f3460;
  color: #7ab8ff;
  border-color: #2a4a6a;
}

.settings-panel {
  background: #16213e;
  padding: 12px 20px;
  border-radius: 12px;
  margin-bottom: 16px;
  border: 1px solid #1a4a7a;
}

.settings-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.settings-label {
  font-size: 12px;
  font-weight: 600;
  color: #888;
  white-space: nowrap;
}

.settings-input {
  flex: 1;
  max-width: 280px;
  padding: 5px 10px;
  background: #0f3460;
  border: 1px solid #1a4a7a;
  border-radius: 6px;
  color: #e0e0e0;
  font-size: 13px;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  outline: none;
}

.settings-input:focus {
  border-color: #60d394;
}

.settings-hint {
  font-size: 11px;
  color: #60d394;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
}

.settings-hint.settings-warn {
  color: #ff6b6b;
}
</style>
