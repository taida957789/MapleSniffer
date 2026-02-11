<script setup lang="ts">
import { ref, watch } from 'vue'
import { getScript, saveScript as bridgeSaveScript } from '../bridge'
import { EditorView, basicSetup } from 'codemirror'
import { keymap } from '@codemirror/view'
import { indentWithTab } from '@codemirror/commands'
import { javascript } from '@codemirror/lang-javascript'
import { oneDark } from '@codemirror/theme-one-dark'
import { linter, lintGutter } from '@codemirror/lint'

const props = defineProps<{
  visible: boolean
  direction: string
  opcode: number
  locale: number
  version: number
}>()

const emit = defineEmits<{
  close: []
  saved: []
}>()

const code = ref('')
const saving = ref(false)
const feedback = ref('')
const feedbackType = ref<'success' | 'error'>('success')
const editorEl = ref<HTMLDivElement | null>(null)
let editorView: EditorView | null = null

const jsLinter = linter((view) => {
  const doc = view.state.doc.toString()
  if (!doc.trim()) return []
  try {
    new Function('packet', doc)
    return []
  } catch (e: any) {
    // Try to extract line info from error message
    const match = e.message?.match(/\((\d+):(\d+)\)/)
    let from = doc.length
    let to = doc.length
    if (match) {
      // SyntaxError line numbers are 2-indexed (wrapper function adds a line)
      const line = Math.max(1, parseInt(match[1]) - 1)
      const col = parseInt(match[2])
      if (line <= view.state.doc.lines) {
        const lineObj = view.state.doc.line(line)
        from = Math.min(lineObj.from + col - 1, lineObj.to)
        to = lineObj.to
      }
    }
    return [{
      from,
      to,
      severity: 'error' as const,
      message: e.message?.replace(/\s*\(\d+:\d+\)$/, '') || 'Syntax error',
    }]
  }
})

function createEditor(container: HTMLElement, initialDoc: string) {
  return new EditorView({
    doc: initialDoc,
    parent: container,
    extensions: [
      basicSetup,
      keymap.of([indentWithTab]),
      javascript(),
      oneDark,
      jsLinter,
      lintGutter(),
      EditorView.theme({
        '&': { height: '100%' },
        '.cm-scroller': { overflow: 'auto' },
        '.cm-content': { fontFamily: "'Cascadia Code', 'Fira Code', 'Consolas', monospace", fontSize: '13px' },
        '.cm-gutters': { background: '#0a2744', borderRight: '1px solid #1a4a7a' },
        '&.cm-editor': { background: '#0f3460' },
        '&.cm-focused': { outline: 'none' },
      }),
      EditorView.updateListener.of((update) => {
        if (update.docChanged) {
          code.value = update.state.doc.toString()
        }
      }),
    ],
  })
}

watch(() => props.visible, async (visible) => {
  if (visible) {
    feedback.value = ''
    try {
      code.value = await getScript(props.direction, props.opcode, props.locale, props.version)
      if (!code.value) {
        code.value = `// Parse opcode 0x${props.opcode.toString(16).toUpperCase().padStart(4, '0')} (${props.direction})\n// Available methods:\n//   packet.readByte(name), packet.readShort(name)\n//   packet.readInt(name), packet.readLong(name)\n//   packet.readString(name, size), packet.readMapleString(name)\n//   packet.readBytes(name, len), packet.readFileTime(name)\n//   packet.readObject(name, fn), packet.readArray(name, count|null, fn)\n//   packet.skip(name, len), packet.remaining()\n\n`
      }
    } catch {
      code.value = ''
    }
    // Wait for DOM to render the container div
    await new Promise(r => setTimeout(r, 0))
    if (editorEl.value) {
      editorView = createEditor(editorEl.value, code.value)
    }
  } else {
    if (editorView) {
      editorView.destroy()
      editorView = null
    }
  }
})

async function save() {
  saving.value = true
  feedback.value = ''

  // Syntax check before saving
  try {
    new Function('packet', code.value)
  } catch (e: any) {
    feedback.value = `Syntax error: ${e.message}`
    feedbackType.value = 'error'
    saving.value = false
    return
  }

  try {
    const ok = await bridgeSaveScript(props.direction, props.opcode, code.value, props.locale, props.version)
    if (ok) {
      feedback.value = 'Saved'
      feedbackType.value = 'success'
      emit('saved')
    } else {
      feedback.value = 'Failed to save'
      feedbackType.value = 'error'
    }
  } catch (e: any) {
    feedback.value = e?.message || 'Save error'
    feedbackType.value = 'error'
  }
  saving.value = false
}

function formatOpcodeHex(op: number): string {
  return '0x' + op.toString(16).toUpperCase().padStart(4, '0')
}
</script>

<template>
  <div v-if="visible" class="editor-overlay" @click.self="emit('close')">
    <div class="editor-dialog">
      <div class="editor-header">
        <span class="editor-title">Script: {{ direction }}_{{ formatOpcodeHex(opcode) }}.js</span>
        <button class="editor-close" @click="emit('close')">&times;</button>
      </div>
      <div ref="editorEl" class="editor-container"></div>
      <div class="editor-footer">
        <span v-if="feedback" class="editor-feedback" :class="feedbackType">{{ feedback }}</span>
        <div class="editor-actions">
          <button class="btn-cancel" @click="emit('close')">Cancel</button>
          <button class="btn-save" :disabled="saving" @click="save">
            {{ saving ? 'Saving...' : 'Save' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.editor-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.editor-dialog {
  background: #16213e;
  border-radius: 12px;
  width: 700px;
  max-width: 90vw;
  max-height: 80vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
}

.editor-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid #1a4a7a;
}

.editor-title {
  font-size: 14px;
  font-weight: 600;
  color: #e0e0e0;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
}

.editor-close {
  background: none;
  border: none;
  color: #888;
  font-size: 22px;
  cursor: pointer;
  padding: 0 4px;
  line-height: 1;
}

.editor-close:hover {
  color: #e0e0e0;
  opacity: 1;
}

.editor-container {
  flex: 1;
  min-height: 350px;
  overflow: hidden;
  border-radius: 0;
}

.editor-container :deep(.cm-editor) {
  height: 100%;
}

.editor-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 20px;
  border-top: 1px solid #1a4a7a;
}

.editor-feedback {
  font-size: 13px;
  font-weight: 600;
}

.editor-feedback.success {
  color: #60d394;
}

.editor-feedback.error {
  color: #ff6b6b;
}

.editor-actions {
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

.btn-save {
  padding: 6px 16px;
  background: #60d394;
  color: #1a1a2e;
  border: none;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
}

.btn-save:disabled {
  opacity: 0.5;
  cursor: default;
}
</style>
