# MapleSniffer

A real-time MapleStory packet sniffer and analyzer with AES decryption, custom parsing scripts, and a modern web UI.

## Features

- **Live Packet Capture** -- npcap-based capture with TCP reassembly, multi-session tracking, and BPF filtering
- **AES Decryption** -- MapleStory AES-256 ECB decryption with automatic IV shifting and header validation
- **Handshake Detection** -- Extracts version, subversion, locale, and server port from handshake packets
- **Script System** -- JavaScript-based per-opcode parsing scripts with a built-in editor
- **Opcode Naming** -- Import/export opcode name maps, per-locale and per-version storage
- **Hex Highlighting** -- Click a parsed field in the TreeView to highlight corresponding bytes in the hex dump
- **Filtering** -- Filter packets by direction (IN/OUT), opcode, name, or content (hex/ASCII search)
- **Multi-Session** -- Track multiple concurrent game sessions with per-session tabs

## Architecture

```
src/
  app/          Saucer webview shell (C++ <-> JS bridge)
  capture/      npcap packet capture
  protocol/     MapleStory protocol: AES, TCP streams, handshake
frontend/
  src/
    App.vue             Main UI (packet list, detail panel, hex dump)
    bridge.ts           C++ <-> JS bridge API
    packet-reader.ts    Script API for parsing packets
    script-engine.ts    Script executor
    components/
      TreeView.vue      Hierarchical parsed field display
      ScriptEditor.vue  Per-opcode script editor
      OpcodeImporter.vue Bulk opcode name import/export
```

## Requirements

- Windows x64
- Visual Studio 2022 (MSVC compiler)
- CMake 3.21+
- [npcap](https://npcap.com/) (runtime driver)
- Node.js 22+ (for frontend build)
- vcpkg (for C++ dependencies)

## Build

### Frontend

```bash
cd frontend
npm install
npm run build
```

### C++ (using build.bat)

```bash
.\build.bat
```

### C++ (manual)

```bash
# From VS Developer Command Prompt (or run vcvarsall.bat x64)
cmake --preset x64-debug
cmake --build out/build/x64-debug
```

The frontend is embedded into the binary via `saucer_embed()`. Rebuild the C++ app after changing the frontend.

## Script API

Parsing scripts are JavaScript functions that receive a `packet` (PacketReader) object. Example:

```javascript
// Parse LP_UserChat (0x0031 recv)
const type = packet.readByte("type")
const message = packet.readMapleString("message")
const show = packet.readByte("show")
```

### Available Methods

| Method | Description |
|---|---|
| `packet.readByte(name)` | Unsigned 8-bit integer |
| `packet.readShort(name)` | Unsigned 16-bit LE integer |
| `packet.readInt(name)` | Unsigned 32-bit LE integer |
| `packet.readLong(name)` | Unsigned 64-bit LE integer (BigInt) |
| `packet.readString(name, size)` | Fixed-length UTF-8 string |
| `packet.readMapleString(name)` | 2-byte length prefix + string |
| `packet.readFileTime(name)` | 8-byte Windows FILETIME (displayed as datetime) |
| `packet.readBytes(name, len)` | Raw bytes (displayed as hex) |
| `packet.readObject(name, fn)` | Grouped child fields |
| `packet.readArray(name, count\|null, fn)` | Array; `null` count reads a 2-byte prefix |
| `packet.skip(name, len)` | Skip bytes |
| `packet.remaining()` | Bytes remaining in buffer |
| `packet.position()` | Current read offset |

## Dependencies

**C++ (vcpkg + FetchContent):**
- nlohmann-json
- OpenSSL
- saucer v8.0.4

**Frontend (npm):**
- Vue 3.4+
- TypeScript 5.3+
- Vite 5

## License

Private project.
