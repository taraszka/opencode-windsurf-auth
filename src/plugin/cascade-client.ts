/**
 * Connect-protocol client for Windsurf Cascade RPC
 *
 * Used for enum-less models (Claude 4.6+) that require SendUserCascadeMessage
 * instead of RawGetChatMessage. Uses HTTP/1.1 Connect protocol (application/proto)
 * rather than HTTP/2 gRPC (application/grpc).
 *
 * Flow:
 * 1. Open streaming connection to StreamCascadeReactiveUpdates
 * 2. Send unary SendUserCascadeMessage with model_uid
 * 3. Read text chunks from the streaming response
 */

import * as http from 'http';
import * as crypto from 'crypto';
import { WindsurfCredentials, WindsurfError, WindsurfErrorCode } from './auth.js';
import { getMetadataFields } from './discovery.js';

// ============================================================================
// Protobuf Encoding Helpers (same as grpc-client but without gRPC framing)
// ============================================================================

function encodeVarint(value: number | bigint): number[] {
  const bytes: number[] = [];
  let v = BigInt(value);
  while (v > 127n) {
    bytes.push(Number(v & 0x7fn) | 0x80);
    v >>= 7n;
  }
  bytes.push(Number(v));
  return bytes;
}

function encodeTag(fieldNum: number, wireType: number): number[] {
  return encodeVarint((fieldNum << 3) | wireType);
}

function encodeString(fieldNum: number, str: string): number[] {
  const strBytes = Buffer.from(str, 'utf8');
  return [...encodeTag(fieldNum, 2), ...encodeVarint(strBytes.length), ...strBytes];
}

function encodeMessage(fieldNum: number, data: number[]): number[] {
  return [...encodeTag(fieldNum, 2), ...encodeVarint(data.length), ...data];
}

function encodeVarintField(fieldNum: number, value: number | bigint): number[] {
  return [...encodeTag(fieldNum, 0), ...encodeVarint(value)];
}

// ============================================================================
// Connect Protocol Helpers
// ============================================================================

function connectPost(
  port: number,
  path: string,
  csrfToken: string,
  body: Buffer
): Promise<{ status: number; data: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method: 'POST',
        headers: {
          'content-type': 'application/proto',
          'connect-protocol-version': '1',
          'x-codeium-csrf-token': csrfToken,
          'accept-encoding': 'identity', // no compression for simplicity
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({ status: res.statusCode || 0, data: Buffer.concat(chunks) });
        });
      }
    );
    req.on('error', (err) => reject(err));
    req.write(body);
    req.end();
  });
}

// ============================================================================
// Model UID Resolution for Cascade
// ============================================================================

import { ModelEnum } from './types.js';

/** Reverse map: enum value → enum name (e.g., 359 → "MODEL_SWE_1_5") */
const ENUM_VALUE_TO_NAME: Record<number, string> = {};
for (const [name, value] of Object.entries(ModelEnum)) {
  ENUM_VALUE_TO_NAME[value as number] = 'MODEL_' + name;
}

/**
 * Resolve the Cascade model UID for a given model.
 * - Enum-less models (4.6): use the server UID directly (e.g., "claude-opus-4-6")
 * - Enum-based models (fallback): use the enum NAME (e.g., "MODEL_SWE_1_5")
 */
export function getCascadeModelUid(modelId: string, enumValue: number): string {
  if (enumValue === 0) return modelId; // Already a server UID
  return ENUM_VALUE_TO_NAME[enumValue] || modelId;
}

// ============================================================================
// Request Building
// ============================================================================

function buildMetadata(apiKey: string, version: string): number[] {
  const fields = getMetadataFields();
  return [
    ...encodeString(fields.api_key, apiKey),
    ...encodeString(fields.ide_name, 'windsurf'),
    ...encodeString(fields.ide_version, version),
    ...encodeString(fields.extension_version, version),
    ...(fields.session_id ? encodeString(fields.session_id, crypto.randomUUID()) : []),
    ...(fields.locale ? encodeString(fields.locale, 'en') : []),
  ];
}

/**
 * Build CascadeConfig with model_uid in planner_config.
 * Structure from ngrep capture:
 *   Field 1 (planner_config):
 *     Field 2: nested { Field 4: varint 1 }
 *     Field 13: empty bytes
 *     Field 35: model_uid string
 *   Field 7 (brain_config):
 *     Field 1: varint 1
 *     Field 6: nested { Field 6: empty bytes }
 *     Field 14: "MODEL_UNSPECIFIED"
 */
function buildCascadeConfig(modelUid: string): number[] {
  // planner_config (field 1)
  const plannerConfig = [
    ...encodeMessage(2, encodeVarintField(4, 1)),
    ...encodeMessage(13, []), // empty
    ...encodeString(35, modelUid),
  ];

  // brain_config (field 7)
  const brainConfig = [
    ...encodeVarintField(1, 1),
    ...encodeMessage(6, encodeMessage(6, [])),
    ...encodeString(14, 'MODEL_UNSPECIFIED'),
  ];

  return [
    ...encodeMessage(1, plannerConfig),
    ...encodeMessage(7, brainConfig),
  ];
}

/**
 * Build TextOrScopeItem for user message.
 * From capture: Field 2 inner = { Field 1: text string }
 */
function buildTextItem(text: string): number[] {
  return encodeString(1, text);
}

/**
 * Build SendUserCascadeMessageRequest
 */
function buildSendUserCascadeMessageRequest(
  apiKey: string,
  version: string,
  cascadeId: string,
  modelUid: string,
  message: string
): Buffer {
  const request: number[] = [];

  // Field 1: cascade_id
  request.push(...encodeString(1, cascadeId));

  // Field 2: items (TextOrScopeItem)
  request.push(...encodeMessage(2, buildTextItem(message)));

  // Field 3: metadata
  const metadata = buildMetadata(apiKey, version);
  request.push(...encodeMessage(3, metadata));

  // Field 5: cascade_config
  const cascadeConfig = buildCascadeConfig(modelUid);
  request.push(...encodeMessage(5, cascadeConfig));

  return Buffer.from(request);
}

/**
 * Build StreamCascadeReactiveUpdates request (StreamReactiveUpdatesRequest)
 * Field 1: protocol_version (varint)
 * Field 2: id (string) = cascade_id
 */
function buildStreamReactiveUpdatesRequest(cascadeId: string): Buffer {
  const request: number[] = [];
  request.push(...encodeVarintField(1, 1)); // protocol_version = 1
  request.push(...encodeString(2, cascadeId));
  return Buffer.from(request);
}

// ============================================================================
// Response Extraction
// ============================================================================


// ============================================================================
// Session Management
// ============================================================================

/** Cache cascade_id per model for multi-turn conversations. */
const cascadeSessionCache = new Map<string, string>();

// ============================================================================
// Public API
// ============================================================================

export interface CascadeChatMessage {
  role: 'user' | 'assistant' | 'system' | 'tool';
  content: string;
}

/**
 * Stream chat via Cascade protocol for enum-less models.
 *
 * Uses Connect protocol (HTTP/1.1 + application/proto) with:
 * 1. StreamCascadeReactiveUpdates (server streaming) for receiving response
 * 2. SendUserCascadeMessage (unary) for sending the request
 */
export async function* streamCascadeChat(
  credentials: WindsurfCredentials,
  options: { model: string; messages: CascadeChatMessage[] }
): AsyncGenerator<string, void, unknown> {
  const { csrfToken, port, apiKey, version } = credentials;
  const modelUid = options.model; // Already the server model UID (e.g., "claude-opus-4-6")

  // Only send the LAST user message — Cascade maintains history server-side.
  // Sending all messages would duplicate context the server already has.
  const userMessages = options.messages.filter(m => m.role === 'user');
  const userMessage = userMessages.length > 0
    ? userMessages[userMessages.length - 1].content
    : '';

  // Step 1: Reuse existing cascade session or start a new one.
  // This enables multi-turn conversations within the same model.
  let serverCascadeId = cascadeSessionCache.get(modelUid);

  if (!serverCascadeId) {
    const startBody = Buffer.from(encodeMessage(1, buildMetadata(apiKey, version)));
    const startResult = await connectPost(
      port,
      '/exa.language_server_pb.LanguageServerService/StartCascade',
      csrfToken,
      startBody
    );
    if (startResult.status !== 200) {
      throw new WindsurfError(
        `StartCascade failed: ${startResult.data.toString('utf8')}`,
        WindsurfErrorCode.CONNECTION_FAILED
      );
    }
    // Extract cascade_id (field 1 string) from StartCascadeResponse
    serverCascadeId = (() => {
      const data = startResult.data;
      if (data.length < 3) return crypto.randomUUID();
      if (data[0] === 0x0a) {
        let len = 0, shift = 0, off = 1;
        while (off < data.length) {
          const b = data[off++];
          len |= (b & 0x7f) << shift;
          if (!(b & 0x80)) break;
          shift += 7;
        }
        if (off + len <= data.length) {
          return data.subarray(off, off + len).toString('utf8');
        }
      }
      return crypto.randomUUID();
    })();
    cascadeSessionCache.set(modelUid, serverCascadeId);
  }

  // Step 2: Open streaming connection (envelope-framed Connect protocol)
  const streamProto = buildStreamReactiveUpdatesRequest(serverCascadeId);
  const streamEnvelope = Buffer.alloc(5 + streamProto.length);
  streamEnvelope.writeUInt32BE(streamProto.length, 1);
  streamProto.copy(streamEnvelope, 5);

  // Step 2b: Set up frame queue and idle-based completion
  const frameQueue: Buffer[] = [];
  let streamDone = false;
  let resolveWait: (() => void) | null = null;
  let messageSent = false;
  let idleTimer: ReturnType<typeof setTimeout> | null = null;

  const streamReq = http.request(
    {
      hostname: '127.0.0.1',
      port,
      path: '/exa.language_server_pb.LanguageServerService/StreamCascadeReactiveUpdates',
      method: 'POST',
      headers: {
        'content-type': 'application/connect+proto',
        'connect-protocol-version': '1',
        'x-codeium-csrf-token': csrfToken,
      },
    },
    (res) => {
      res.on('data', (chunk: Buffer) => {
        // Parse Connect envelope frames from chunk
        let off = 0;
        while (off + 5 <= chunk.length) {
          const flags = chunk[off];
          const len = chunk.readUInt32BE(off + 1);
          off += 5;
          if (off + len > chunk.length) break;
          if (flags !== 2) {
            frameQueue.push(chunk.subarray(off, off + len));
          }
          off += len;
        }
        // Reset idle timer — settle 5s after last frame
        if (messageSent) {
          if (idleTimer) clearTimeout(idleTimer);
          idleTimer = setTimeout(() => { streamDone = true; resolveWait?.(); }, 20000);
        }
        resolveWait?.();
      });
      res.on('end', () => { streamDone = true; resolveWait?.(); });
      res.on('error', () => { streamDone = true; resolveWait?.(); });
    }
  );
  streamReq.on('error', () => { streamDone = true; resolveWait?.(); });
  streamReq.write(streamEnvelope);
  streamReq.end();
  setTimeout(() => { streamDone = true; resolveWait?.(); }, 180000);

  await new Promise((r) => setTimeout(r, 300));

  // Step 3: Send the user message
  const sendBody = buildSendUserCascadeMessageRequest(
    apiKey,
    version,
    serverCascadeId,
    modelUid,
    userMessage
  );
  const sendResult = await connectPost(
    port,
    '/exa.language_server_pb.LanguageServerService/SendUserCascadeMessage',
    csrfToken,
    sendBody
  );
  if (sendResult.status !== 200) {
    // If the session is stale, clear cache and let the next request create a fresh one
    cascadeSessionCache.delete(modelUid);
    throw new WindsurfError(
      `SendUserCascadeMessage failed: ${sendResult.data.toString('utf8')}`,
      WindsurfErrorCode.STREAM_ERROR
    );
  }

  // Signal message sent — start idle timer
  messageSent = true;
  idleTimer = setTimeout(() => { streamDone = true; resolveWait?.(); }, 5000);

  // Step 4: Wait for frames to settle (5s idle after last frame), then extract.
  // The Cascade stream never ends naturally — it's long-lived.
  // Frames arrive in bursts during each agent turn. A 5s gap after
  // the last frame reliably indicates the agent has finished.
  while (!streamDone) {
    await new Promise<void>((r) => { resolveWait = r; });
    resolveWait = null;
  }

  try { streamReq.destroy(); } catch {}

  // Extract response: scan ALL frames for the FIRST printable text with spaces
  // that appears AFTER the user message frame. The actual response comes early
  // in the stream; planner summaries come late. Skip known noise patterns.
  let userSeen = false;
  let bestResponse = '';

  for (const frame of frameQueue) {
    const text = frame.toString('utf8');

    // Skip until we see user message echoed back
    if (!userSeen) {
      if (text.includes(userMessage.substring(0, Math.min(15, userMessage.length)))) {
        userSeen = true;
      }
      continue;
    }

    // Scan for printable text runs with spaces
    const matches = [...text.matchAll(/[\x20-\x7e\n\r\t]{5,}/g)];
    for (const m of matches) {
      const candidate = m[0].trim();
      if (!candidate.includes(' ')) continue;
      if (candidate.length <= 3) continue;

      // Skip noise
      if (/^[a-f0-9-]{10,}$/.test(candidate)) continue;
      if (/Response Statistics|Input tokens|Output tokens|Token Usage|Cached input|Credits spent/i.test(candidate)) continue;
      if (/Claude (Opus|Sonnet)|^MODEL_|^windsurf$/i.test(candidate)) continue;
      if (/<\w+_\w+>/.test(candidate)) continue;
      if (/main objective|user'?s .*(objective|goal|request)|await further|was completed in the previou/i.test(candidate)) continue;
      if (/You are (Cascade|OpenCode)/i.test(candidate)) continue;
      if (/CRITICAL REQUIREMENTS|old_string|new_string|TodoWrite/i.test(candidate)) continue;
      if (/^(say |describe |explain |create |write |list |compare )/i.test(candidate) && candidate.length < 50) continue; // user prompt echo

      // Clean protobuf tag artifacts: leading "z" + length byte, trailing junk
      let cleaned = candidate
        .replace(/^[#\/%&\*\+].?z.[\n\r]?/g, '')  // leading tag: #z!, /z-, etc
        .replace(/^z.[\n\r]?/, '')                   // bare z + length
        .replace(/[\n\r]?[&\*#\/%]$/g, '')           // trailing artifacts
        .trim();

      if (cleaned.length < 4) continue;

      // First valid text = the response (it comes before planner summary)
      if (cleaned.length > bestResponse.length) {
        bestResponse = cleaned;
      }
      // Stop after finding the first substantial match
      if (bestResponse.length > 10) break;
    }
    if (bestResponse.length > 10) break;
  }

  if (bestResponse) {
    // Format Cascade tool call JSON (e.g., ask_user_question) into readable text
    const trimmed = bestResponse.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed.question && typeof parsed.question === 'string') {
          let formatted = parsed.question;
          if (Array.isArray(parsed.options)) {
            formatted += '\n\n';
            for (const opt of parsed.options) {
              if (opt.label) {
                formatted += `- **${opt.label}**`;
                if (opt.description) formatted += `: ${opt.description}`;
                formatted += '\n';
              }
            }
          }
          yield formatted;
          return;
        }
        if (parsed.action === 'final' && parsed.content) {
          yield parsed.content;
          return;
        }
      } catch { /* not JSON, yield as-is */ }
    }
    yield bestResponse;
  }
}

/**
 * Check if a model requires the Cascade protocol (no protobuf enum).
 */
export function requiresCascadeProtocol(enumValue: number): boolean {
  return enumValue === 0; // MODEL_UNSPECIFIED means enum-less model
}
