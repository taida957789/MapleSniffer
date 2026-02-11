<script setup lang="ts">
import { ref } from 'vue'
import type { ParsedField } from '../packet-reader'

defineProps<{
  fields: ParsedField[]
  depth?: number
  selectedOffset?: number
  selectedLength?: number
}>()

const emit = defineEmits<{
  select: [offset: number, length: number]
}>()

const collapsed = ref<Set<string>>(new Set())

function toggleKey(key: string) {
  if (collapsed.value.has(key)) collapsed.value.delete(key)
  else collapsed.value.add(key)
}

function isCollapsed(key: string): boolean {
  return collapsed.value.has(key)
}

function formatValue(field: ParsedField): string {
  if (field.type === 'object') return ''
  if (field.type === 'array') return ''
  if (field.type === 'string') return `"${field.value}"`
  if (field.type === 'bytes') return field.value
  if (field.type === 'long') return field.value
  if (field.type === 'int' || field.type === 'short' || field.type === 'byte') {
    return `${field.value} (0x${field.value.toString(16).toUpperCase()})`
  }
  return String(field.value)
}

function fieldKey(field: ParsedField, index: number, depth: number): string {
  return `${depth}-${index}-${field.offset}`
}

function onRowClick(field: ParsedField, key: string) {
  emit('select', field.offset, field.length)
  if (field.children) toggleKey(key)
}
</script>

<template>
  <div class="tree-view">
    <div
      v-for="(field, i) in fields"
      :key="fieldKey(field, i, depth ?? 0)"
      class="tree-node"
    >
      <div
        class="tree-row"
        :class="{ selected: field.offset === selectedOffset && field.length === selectedLength }"
        :style="{ paddingLeft: ((depth ?? 0) * 16 + 4) + 'px' }"
        @click="onRowClick(field, fieldKey(field, i, depth ?? 0))"
      >
        <span v-if="field.children" class="tree-toggle">
          {{ isCollapsed(fieldKey(field, i, depth ?? 0)) ? '&#9654;' : '&#9660;' }}
        </span>
        <span v-else class="tree-leaf">&bull;</span>
        <span class="tree-name">{{ field.name }}</span>
        <span v-if="field.type !== 'object' && field.type !== 'array'" class="tree-sep">: </span>
        <span class="tree-value" :class="'type-' + field.type">{{ formatValue(field) }}</span>
        <span class="tree-offset">@{{ field.offset }}</span>
      </div>
      <TreeView
        v-if="field.children && !isCollapsed(fieldKey(field, i, depth ?? 0))"
        :fields="field.children"
        :depth="(depth ?? 0) + 1"
        :selected-offset="selectedOffset"
        :selected-length="selectedLength"
        @select="(offset: number, length: number) => emit('select', offset, length)"
      />
    </div>
  </div>
</template>

<style scoped>
.tree-view {
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.7;
}

.tree-row {
  display: flex;
  align-items: baseline;
  gap: 4px;
  cursor: pointer;
  border-radius: 3px;
  padding-right: 8px;
}

.tree-row:hover {
  background: rgba(255, 255, 255, 0.04);
}

.tree-row.selected {
  background: rgba(58, 106, 154, 0.3);
}

.tree-toggle {
  font-size: 9px;
  width: 12px;
  cursor: pointer;
  color: #888;
  flex-shrink: 0;
}

.tree-leaf {
  width: 12px;
  color: #555;
  flex-shrink: 0;
  font-size: 10px;
}

.tree-name {
  color: #c0c0c0;
  font-weight: 600;
  white-space: nowrap;
}

.tree-sep {
  color: #666;
}

.tree-value {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.tree-value.type-string {
  color: #60d394;
}

.tree-value.type-byte,
.tree-value.type-short,
.tree-value.type-int,
.tree-value.type-long {
  color: #ffd166;
}

.tree-value.type-bytes {
  color: #7ab8ff;
}

.tree-offset {
  color: #555;
  font-size: 10px;
  margin-left: auto;
  flex-shrink: 0;
}
</style>
