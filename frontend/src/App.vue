<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'

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
let pollTimer: ReturnType<typeof setInterval> | null = null

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
      // Prepend newest first (reverse new batch, then prepend)
      packets.value.unshift(...newPackets.reverse())
      // Keep only 500
      if (packets.value.length > 500) {
        packets.value = packets.value.slice(0, 500)
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
      <h2>Packets ({{ packets.length }})</h2>
      <div class="packet-list">
        <div v-if="packets.length === 0" class="empty">
          No packets captured yet.
        </div>
        <div v-for="pkt in packets" :key="pkt.index" class="packet-item" :class="{ handshake: pkt.isHandshake }">
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
          <pre class="pkt-hex">{{ pkt.hexDump }}</pre>
        </div>
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

.packets h2 {
  font-size: 18px;
  margin-bottom: 12px;
  color: #aaa;
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
</style>
