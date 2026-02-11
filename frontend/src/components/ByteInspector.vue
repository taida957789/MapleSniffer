<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  bytes: number[]
  visible: boolean
}>()

const buf = computed(() => new Uint8Array(props.bytes))
const dv = computed(() => new DataView(buf.value.buffer))
const len = computed(() => props.bytes.length)

function fmt(n: number | bigint): string {
  const s = n.toString()
  if (typeof n === 'bigint' || Math.abs(Number(n)) >= 1_000_000) return s
  return s
}

function hex(n: number | bigint, bits: number): string {
  const h = (typeof n === 'bigint' ? n : BigInt(n)).toString(16).toUpperCase()
  return '0x' + h.padStart(bits / 4, '0')
}

const interpretations = computed(() => {
  if (len.value === 0) return []
  const results: { type: string; value: string; hex: string }[] = []
  const d = dv.value
  const n = len.value

  // uint8 / int8
  results.push({ type: 'uint8', value: fmt(d.getUint8(0)), hex: hex(d.getUint8(0), 8) })
  results.push({ type: 'int8', value: fmt(d.getInt8(0)), hex: hex(d.getUint8(0), 8) })

  // uint16 / int16 LE
  if (n >= 2) {
    results.push({ type: 'uint16 LE', value: fmt(d.getUint16(0, true)), hex: hex(d.getUint16(0, true), 16) })
    results.push({ type: 'int16 LE', value: fmt(d.getInt16(0, true)), hex: hex(d.getUint16(0, true), 16) })
  }

  // uint32 / int32 LE
  if (n >= 4) {
    results.push({ type: 'uint32 LE', value: fmt(d.getUint32(0, true)), hex: hex(d.getUint32(0, true), 32) })
    results.push({ type: 'int32 LE', value: fmt(d.getInt32(0, true)), hex: hex(d.getInt32(0, true) >>> 0, 32) })
  }

  // uint64 / int64 LE
  if (n >= 8) {
    results.push({ type: 'uint64 LE', value: fmt(d.getBigUint64(0, true)), hex: hex(d.getBigUint64(0, true), 64) })
    results.push({ type: 'int64 LE', value: fmt(d.getBigInt64(0, true)), hex: hex(d.getBigUint64(0, true), 64) })
  }

  // Float LE
  if (n >= 4) {
    const f = d.getFloat32(0, true)
    results.push({ type: 'Float LE', value: isFinite(f) ? f.toPrecision(7) : String(f), hex: hex(d.getUint32(0, true), 32) })
  }

  // Double LE
  if (n >= 8) {
    const f = d.getFloat64(0, true)
    results.push({ type: 'Double LE', value: isFinite(f) ? f.toPrecision(15) : String(f), hex: hex(d.getBigUint64(0, true), 64) })
  }

  // String (UTF-8, non-printable as dots)
  const str = Array.from(buf.value).map(b => (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.').join('')
  results.push({ type: 'String', value: str, hex: '' })

  // FILETIME (Windows 100ns ticks since 1601-01-01)
  if (n >= 8) {
    const low = d.getUint32(0, true)
    const high = d.getUint32(4, true)
    const filetime = BigInt(low) | (BigInt(high) << 32n)
    const FILETIME_EPOCH_DIFF = 11644473600000n
    const FILETIME_ONE_MS = 10000n
    if (filetime === 0n) {
      results.push({ type: 'FILETIME', value: '(zero)', hex: '' })
    } else {
      const epochMs = Number(filetime / FILETIME_ONE_MS - FILETIME_EPOCH_DIFF)
      if (epochMs > -30610224000000 && epochMs < 32503680000000) {
        results.push({ type: 'FILETIME', value: new Date(epochMs).toISOString().replace('T', ' ').replace(/\.000Z$/, ''), hex: '' })
      } else {
        results.push({ type: 'FILETIME', value: '(out of range)', hex: '' })
      }
    }
  }

  // Unix Timestamp
  if (n >= 4) {
    const ts = d.getUint32(0, true)
    if (ts > 946684800 && ts < 2147483647) {
      results.push({ type: 'Unix TS', value: new Date(ts * 1000).toISOString().replace('T', ' ').replace(/\.000Z$/, ''), hex: '' })
    } else {
      results.push({ type: 'Unix TS', value: ts === 0 ? '(zero)' : '(out of range)', hex: '' })
    }
  }

  return results
})
</script>

<template>
  <div v-if="visible && bytes.length > 0" class="byte-inspector">
    <div class="bi-header">
      <span class="bi-title">Byte Inspector</span>
      <span class="bi-count">{{ len }} byte{{ len !== 1 ? 's' : '' }} selected</span>
    </div>
    <table class="bi-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>Value</th>
          <th>Hex</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in interpretations" :key="row.type">
          <td class="bi-type">{{ row.type }}</td>
          <td class="bi-value">{{ row.value }}</td>
          <td class="bi-hex">{{ row.hex }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.byte-inspector {
  background: #0d2b50;
  border: 1px solid #1a4a7a;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6);
}

.bi-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 12px;
  background: #0a2240;
  border-bottom: 1px solid #1a4a7a;
}

.bi-title {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #50c8c8;
}

.bi-count {
  font-size: 11px;
  color: #888;
}

.bi-table {
  width: 100%;
  border-collapse: collapse;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  font-size: 12px;
}

.bi-table th {
  text-align: left;
  padding: 4px 10px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #666;
  border-bottom: 1px solid #1a4a7a;
}

.bi-table td {
  padding: 3px 10px;
  border-bottom: 1px solid #122a48;
}

.bi-table tr:last-child td {
  border-bottom: none;
}

.bi-table tr:hover {
  background: #112a50;
}

.bi-type {
  color: #888;
  white-space: nowrap;
  width: 90px;
}

.bi-value {
  color: #e0e0e0;
  word-break: break-all;
}

.bi-hex {
  color: #7ab8ff;
  white-space: nowrap;
}
</style>
