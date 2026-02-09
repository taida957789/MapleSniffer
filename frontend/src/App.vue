<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'

interface NetworkInterface {
  name: string
  friendlyName: string
  description: string
}

interface PacketInfo {
  index: number
  timestamp: number
  length: number
  hexDump: string
  outbound: boolean
  opcode: string
  opcodeRaw: number
  isHandshake: boolean
  decrypted: boolean
  version?: number
  subVersion?: string
  locale?: number
}

interface Status {
  capturing: boolean
  packetCount: number
  interface: string
  filter: string
}

const interfaces = ref<NetworkInterface[]>([])
const selectedInterface = ref('')
const portMin = ref(8484)
const portMax = ref(9999)
const status = ref<Status>({ capturing: false, packetCount: 0, interface: '', filter: '' })
const packets = ref<PacketInfo[]>([])
const error = ref('')
const activeTab = ref<'all' | 'in' | 'out'>('all')
const sortOrder = ref<'desc' | 'asc'>('desc')
const opcodeFilter = ref('')
const contentSearch = ref('')
const expandedPackets = ref<Set<number>>(new Set())
let pollTimer: ReturnType<typeof setInterval> | null = null

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
  // Try as hex bytes: "AB CD" or "ABCD" or "ab cd ef"
  const hexNorm = q.replace(/\s+/g, '').toLowerCase()
  if (/^[0-9a-f]+$/.test(hexNorm) && hexNorm.length >= 2 && hexNorm.length % 2 === 0) {
    // Build spaced hex string for substring match
    const hexSpaced = hexNorm.match(/.{2}/g)!.join(' ')
    if (pkt.hexDump.toLowerCase().includes(hexSpaced)) return true
  }
  // Try as ASCII: convert query chars to hex bytes and search
  const asciiHex = Array.from(q).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ')
  if (pkt.hexDump.toLowerCase().includes(asciiHex)) return true
  return false
}

const filteredPackets = computed(() => {
  let list = packets.value
  if (activeTab.value === 'in') list = list.filter(p => !p.outbound)
  else if (activeTab.value === 'out') list = list.filter(p => p.outbound)
  if (opcodeFilter.value) {
    const q = opcodeFilter.value.trim().toLowerCase()
    list = list.filter(p => p.opcode.toLowerCase().includes(q))
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

const inCount = computed(() => packets.value.filter(p => !p.outbound).length)
const outCount = computed(() => packets.value.filter(p => p.outbound).length)

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

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

async function loadInterfaces() {
  try {
    interfaces.value = await fetchJson<NetworkInterface[]>('/api/interfaces')
    // Restore from localStorage or default to first
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
    status.value = await fetchJson<Status>('/api/status')
    // If capturing, restore the active interface selection
    if (status.value.capturing && status.value.interface) {
      selectedInterface.value = status.value.interface
    }
  } catch {}
}

// Track server-side index for incremental fetch
let serverPacketCount = 0

async function loadPackets() {
  try {
    const newPackets = await fetchJson<PacketInfo[]>(`/api/packets?since=${serverPacketCount}`)
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
    await fetchJson('/api/capture/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        interface: selectedInterface.value,
        filter: buildFilter()
      })
    })
    localStorage.setItem('maple_interface', selectedInterface.value)
    error.value = ''
    await loadStatus()
  } catch (e: any) {
    error.value = 'Failed to start capture: ' + e.message
  }
}

async function stopCapture() {
  try {
    await fetchJson('/api/capture/stop', { method: 'POST' })
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

onMounted(async () => {
  await loadInterfaces()
  await loadStatus()
  // If already capturing on mount (page refresh), load existing packets
  if (status.value.capturing) {
    await loadPackets()
  }
  pollTimer = setInterval(() => {
    loadStatus()
    if (status.value.capturing) {
      loadPackets()
    }
  }, 1000)
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<template>
  <div class="app">
    <header>
      <h1>MapleAuto</h1>
      <span class="status-badge" :class="{ active: status.capturing }">
        {{ status.capturing ? 'Capturing' : 'Idle' }}
      </span>
    </header>

    <div v-if="error" class="error">{{ error }}</div>

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

    <section class="packets">
      <div class="packet-toolbar">
        <div class="tabs">
          <button
            class="tab"
            :class="{ active: activeTab === 'all' }"
            @click="switchTab('all')"
          >All ({{ packets.length }})</button>
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
          placeholder="Filter opcode (e.g. 0x00B5)"
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
        <div v-for="pkt in pagedPackets" :key="pkt.index" class="packet-item" :class="{ handshake: pkt.isHandshake }">
          <div class="packet-header">
            <span class="pkt-index">#{{ pkt.index }}</span>
            <span class="pkt-time">{{ formatTimestamp(pkt.timestamp) }}</span>
            <span class="pkt-opcode" :class="{ 'opcode-hs': pkt.isHandshake }">
              {{ pkt.opcode }}
            </span>
            <span class="pkt-dir" :class="{ outbound: pkt.outbound, inbound: !pkt.outbound }">
              {{ pkt.outbound ? '→ OUT' : '← IN' }}
            </span>
            <span class="pkt-len">{{ pkt.length }} B</span>
            <span v-if="pkt.isHandshake" class="pkt-hs-info">
              v{{ pkt.version }}.{{ pkt.subVersion }} locale={{ pkt.locale }}
            </span>
          </div>
          <div class="pkt-hex-wrap">
            <pre class="pkt-hex">{{ isExpanded(pkt.index) ? pkt.hexDump : previewHex(pkt.hexDump) }}</pre>
            <button
              v-if="needsTruncation(pkt.hexDump)"
              class="hex-toggle"
              @click="toggleHex(pkt.index)"
            >{{ isExpanded(pkt.index) ? 'Collapse' : 'Expand' }}</button>
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
  max-width: 960px;
  margin: 0 auto;
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

.error {
  background: #4a1525;
  color: #ff6b6b;
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
  width: 180px;
}

.filter-input:focus {
  border-color: #60d394;
}

.filter-content {
  flex: 1;
}

.packet-list {
  max-height: 600px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.empty {
  text-align: center;
  color: #555;
  padding: 40px 0;
}

.packet-item {
  background: #16213e;
  border-radius: 8px;
  padding: 12px 16px;
}

.packet-item.handshake {
  border-left: 3px solid #f0c040;
}

.packet-header {
  display: flex;
  gap: 12px;
  font-size: 13px;
  margin-bottom: 8px;
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

.pkt-hex-wrap {
  position: relative;
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

.hex-toggle {
  display: block;
  width: 100%;
  padding: 4px 0;
  margin-top: 0;
  background: #0a2a50;
  color: #5a9ad5;
  font-size: 11px;
  font-weight: 600;
  border: none;
  border-radius: 0 0 6px 6px;
  cursor: pointer;
  text-align: center;
}

.hex-toggle:hover {
  background: #0d3260;
  color: #7ab8ff;
  opacity: 1;
}
</style>
