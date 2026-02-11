<script setup lang="ts">
import { ref } from 'vue'
import {
  getOpcodeNames,
  saveOpcodeNames,
  type OpcodeNameMap
} from '../bridge'

const props = defineProps<{
  visible: boolean
  locale: number
  version: number
}>()

const emit = defineEmits<{
  close: []
  imported: []
}>()

const recvText = ref('')
const sendText = ref('')
const feedback = ref('')
const feedbackType = ref<'success' | 'error'>('success')
const importing = ref(false)

function parseValue(s: string): number {
  s = s.trim()
  return s.startsWith('0x') || s.startsWith('0X') ? parseInt(s, 16) : parseInt(s, 10)
}

function parseLines(text: string): Record<string, string> {
  const result: Record<string, string> = {}
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/\/\/.*$/, '').replace(/;/g, '').trim()
    if (!line) continue

    // NAME=0xHEX or NAME = 0xHEX or NAME=DECIMAL
    const m = line.match(/^(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)/)
    if (m) {
      const name = m[1]
      const value = parseValue(m[2])
      if (!isNaN(value) && value >= 0 && value <= 0xFFFF) {
        result[String(value)] = name
      }
    }
  }
  return result
}

function onFileLoad(direction: 'recv' | 'send', event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return

  const reader = new FileReader()
  reader.onload = () => {
    const text = reader.result as string
    if (direction === 'recv') recvText.value = text
    else sendText.value = text
  }
  reader.readAsText(file)
  input.value = ''
}

function formatHex(opcode: number): string {
  return '0x' + opcode.toString(16).toUpperCase().padStart(4, '0')
}

function mapToText(map: Record<string, string>): string {
  return Object.entries(map)
    .sort(([a], [b]) => Number(a) - Number(b))
    .map(([opcodeStr, name]) => `${name}=${formatHex(Number(opcodeStr))}`)
    .join('\n')
}

function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

async function doExport(direction: 'recv' | 'send') {
  try {
    const names = await getOpcodeNames(props.locale, props.version)
    const map = direction === 'recv' ? (names.recv ?? {}) : (names.send ?? {})
    const count = Object.keys(map).length
    if (count === 0) {
      feedback.value = `No ${direction} opcodes to export`
      feedbackType.value = 'error'
      return
    }
    const text = mapToText(map)
    const filename = `${direction}_opcodes_${props.locale}_${props.version}.txt`
    downloadText(filename, text)
    feedback.value = `Exported ${count} ${direction} opcodes`
    feedbackType.value = 'success'
  } catch (e: any) {
    feedback.value = e?.message || 'Export error'
    feedbackType.value = 'error'
  }
}

async function doImport() {
  importing.value = true
  feedback.value = ''
  try {
    // Load existing names to merge
    let existing: OpcodeNameMap
    try {
      existing = await getOpcodeNames(props.locale, props.version)
    } catch {
      existing = { send: {}, recv: {} }
    }
    if (!existing.send) existing.send = {}
    if (!existing.recv) existing.recv = {}

    const parsedRecv = parseLines(recvText.value)
    const parsedSend = parseLines(sendText.value)

    const recvCount = Object.keys(parsedRecv).length
    const sendCount = Object.keys(parsedSend).length

    if (recvCount === 0 && sendCount === 0) {
      feedback.value = 'No valid entries found'
      feedbackType.value = 'error'
      importing.value = false
      return
    }

    // Merge: new values overwrite existing
    Object.assign(existing.recv, parsedRecv)
    Object.assign(existing.send, parsedSend)

    const ok = await saveOpcodeNames(props.locale, props.version, existing)
    if (ok) {
      feedback.value = `Imported ${recvCount} recv + ${sendCount} send opcodes`
      feedbackType.value = 'success'
      emit('imported')
    } else {
      feedback.value = 'Failed to save'
      feedbackType.value = 'error'
    }
  } catch (e: any) {
    feedback.value = e?.message || 'Import error'
    feedbackType.value = 'error'
  }
  importing.value = false
}
</script>

<template>
  <div v-if="visible" class="importer-overlay" @click.self="emit('close')">
    <div class="importer-dialog">
      <div class="importer-header">
        <span class="importer-title">Opcode Names</span>
        <span class="importer-session">{{ locale }}_{{ version }}</span>
        <button class="importer-close" @click="emit('close')">&times;</button>
      </div>

      <div class="importer-body">
        <div class="importer-hint">
          Format: one per line, e.g. <code>LP_SetField=0x0288</code>
        </div>

        <div class="importer-sections">
          <!-- Recv -->
          <div class="importer-section">
            <div class="section-header">
              <span class="section-label">Recv (IN)</span>
              <div class="section-btns">
                <label class="file-btn">
                  Load
                  <input type="file" accept=".txt,.h,.hpp,.cs,.java,.py" @change="onFileLoad('recv', $event)" />
                </label>
                <button class="file-btn" @click="doExport('recv')">Export</button>
              </div>
            </div>
            <textarea
              v-model="recvText"
              class="importer-textarea"
              spellcheck="false"
              placeholder="LP_SetField=0x0288&#10;LP_UserChat=0x00A2&#10;..."
            ></textarea>
          </div>

          <!-- Send -->
          <div class="importer-section">
            <div class="section-header">
              <span class="section-label">Send (OUT)</span>
              <div class="section-btns">
                <label class="file-btn">
                  Load
                  <input type="file" accept=".txt,.h,.hpp,.cs,.java,.py" @change="onFileLoad('send', $event)" />
                </label>
                <button class="file-btn" @click="doExport('send')">Export</button>
              </div>
            </div>
            <textarea
              v-model="sendText"
              class="importer-textarea"
              spellcheck="false"
              placeholder="CP_MigrateIn=0x0026&#10;CP_UserChat=0x0031&#10;..."
            ></textarea>
          </div>
        </div>
      </div>

      <div class="importer-footer">
        <span v-if="feedback" class="importer-feedback" :class="feedbackType">{{ feedback }}</span>
        <div class="importer-actions">
          <button class="btn-cancel" @click="emit('close')">Cancel</button>
          <button class="btn-import" :disabled="importing" @click="doImport">
            {{ importing ? 'Importing...' : 'Import' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.importer-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.importer-dialog {
  background: #16213e;
  border-radius: 12px;
  width: 800px;
  max-width: 95vw;
  max-height: 85vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
}

.importer-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 20px;
  border-bottom: 1px solid #1a4a7a;
}

.importer-title {
  font-size: 14px;
  font-weight: 600;
  color: #e0e0e0;
}

.importer-session {
  font-size: 12px;
  color: #f0c040;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  background: #2a2a1e;
  padding: 2px 8px;
  border-radius: 4px;
}

.importer-close {
  background: none;
  border: none;
  color: #888;
  font-size: 22px;
  cursor: pointer;
  padding: 0 4px;
  line-height: 1;
  margin-left: auto;
}

.importer-close:hover {
  color: #e0e0e0;
  opacity: 1;
}

.importer-body {
  padding: 16px 20px;
  overflow-y: auto;
  flex: 1;
}

.importer-hint {
  font-size: 12px;
  color: #888;
  margin-bottom: 12px;
}

.importer-hint code {
  background: #0f3460;
  padding: 1px 6px;
  border-radius: 3px;
  color: #ffd166;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
}

.importer-sections {
  display: flex;
  gap: 12px;
}

.importer-section {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}

.section-label {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #888;
}

.section-btns {
  display: flex;
  gap: 4px;
}

.file-btn {
  padding: 3px 10px;
  font-size: 11px;
  font-weight: 600;
  background: #0f3460;
  color: #7ab8ff;
  border: 1px solid #1a4a7a;
  border-radius: 4px;
  cursor: pointer;
}

.file-btn:hover {
  background: #1a4a7a;
  color: #e0e0e0;
}

.file-btn input {
  display: none;
}

.importer-textarea {
  flex: 1;
  min-height: 250px;
  padding: 12px;
  background: #0f3460;
  color: #e0e0e0;
  border: 1px solid #1a4a7a;
  border-radius: 6px;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.5;
  resize: none;
  outline: none;
}

.importer-textarea:focus {
  border-color: #60d394;
}

.importer-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 20px;
  border-top: 1px solid #1a4a7a;
}

.importer-feedback {
  font-size: 13px;
  font-weight: 600;
}

.importer-feedback.success {
  color: #60d394;
}

.importer-feedback.error {
  color: #ff6b6b;
}

.importer-actions {
  display: flex;
  gap: 8px;
  margin-left: auto;
}

.btn-cancel {
  padding: 6px 16px;
  background: #1a1a2e;
  color: #aaa;
  border: 1px solid #333;
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
}

.btn-cancel:hover {
  color: #e0e0e0;
  opacity: 1;
}

.btn-import {
  padding: 6px 16px;
  background: #60d394;
  color: #1a1a2e;
  border: none;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
}

.btn-import:disabled {
  opacity: 0.5;
  cursor: default;
}
</style>
