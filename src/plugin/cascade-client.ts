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
// Response Parsing
// ============================================================================

function decodeVarintFromBuf(buffer: Buffer, offset: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  let bytesRead = 0;
  while (offset + bytesRead < buffer.length) {
    const byte = buffer[offset + bytesRead];
    bytesRead++;
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
  }
  return [result, bytesRead];
}

/**
 * Parse protobuf fields from a buffer.
 * Returns array of {fieldNum, wireType, data/value}.
 */
function parseProtoFields(buffer: Buffer): Array<{
  fieldNum: number;
  wireType: number;
  data?: Buffer;
  value?: bigint;
}> {
  const fields: Array<{ fieldNum: number; wireType: number; data?: Buffer; value?: bigint }> = [];
  let offset = 0;
  while (offset < buffer.length) {
    const [tag, tagBytes] = decodeVarintFromBuf(buffer, offset);
    const fieldNum = Number(tag >> 3n);
    const wireType = Number(tag & 0x7n);
    offset += tagBytes;
    if (wireType === 0) {
      const [val, valBytes] = decodeVarintFromBuf(buffer, offset);
      offset += valBytes;
      fields.push({ fieldNum, wireType, value: val });
    } else if (wireType === 2) {
      const [len, lenBytes] = decodeVarintFromBuf(buffer, offset);
      offset += lenBytes;
      const l = Number(len);
      if (offset + l > buffer.length) break;
      fields.push({ fieldNum, wireType, data: buffer.subarray(offset, offset + l) });
      offset += l;
    } else if (wireType === 5) {
      offset += 4;
    } else if (wireType === 1) {
      offset += 8;
    } else {
      break;
    }
  }
  return fields;
}

/**
 * Extract assistant response text from a Cascade reactive update frame.
 *
 * The assistant's text is in f15 strings inside frames that contain a "bot-" UUID.
 * We only extract from frames with the bot marker to avoid system prompt leakage.
 */
function extractContentFromReactiveUpdate(buffer: Buffer): string[] {
  // Only extract from frames containing the bot marker (assistant messages)
  const frameStr = buffer.toString('utf8');
  if (!frameStr.includes('bot-')) return [];

  const texts: string[] = [];

  function collectF15(buf: Buffer): void {
    const fields = parseProtoFields(buf);
    for (const f of fields) {
      if (f.wireType !== 2 || !f.data) continue;
      const str = f.data.toString('utf8');
      const isPrintable = f.data.length > 0 && /^[\x20-\x7e\n\r\t\u00a0-\uffff]+$/.test(str);

      if (f.fieldNum === 15 && isPrintable) {
        // Filter out known metadata strings
        if (
          !/^[a-f0-9-]{10,}$/.test(str) &&
          !/^MODEL_/.test(str) &&
          !/^claude-/.test(str) &&
          !/^\//.test(str) &&
          !/^windsurf$/i.test(str) &&
          !/^bot-/.test(str) &&
          !/^z[\$a-f0-9]/.test(str) &&
          !/^[a-zA-Z0-9]{20,}$/.test(str) && // random ID strings
          !/^(Response Statistics|Credits spent|credits?|model|Model| credits?|yaml|trafficType)$/i.test(str) &&
          !/^Claude (Opus|Sonnet|Haiku|Code)/.test(str)
        ) {
          texts.push(str);
        }
      } else if (!isPrintable && f.data.length > 2) {
        collectF15(f.data);
      }
    }
  }

  collectF15(buffer);

  // Deduplicate (the cascade sends content twice - once in the message, once in a copy)
  const seen = new Set<string>();
  return texts.filter(t => {
    if (seen.has(t)) return false;
    seen.add(t);
    return true;
  });
}

/**
 * Extract ALL f15 printable strings from a protobuf buffer (no bot-marker filter).
 * Used for response frames after the bot marker has been seen.
 */
function extractAllF15Strings(buffer: Buffer): string[] {
  const texts: string[] = [];
  function walk(buf: Buffer): void {
    const fields = parseProtoFields(buf);
    for (const f of fields) {
      if (f.wireType !== 2 || !f.data) continue;
      const str = f.data.toString('utf8');
      const isPrintable = f.data.length > 0 && /^[\x20-\x7e\n\r\t\u00a0-\uffff]+$/.test(str);
      if (f.fieldNum === 15 && isPrintable && f.data.length > 1) {
        texts.push(str);
      } else if (!isPrintable && f.data.length > 2) {
        walk(f.data);
      }
    }
  }
  walk(buffer);
  // Deduplicate
  const seen = new Set<string>();
  return texts.filter(t => {
    if (seen.has(t)) return false;
    seen.add(t);
    return true;
  });
}

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
  const cascadeId = crypto.randomUUID();
  const modelUid = options.model; // Already the server model UID (e.g., "claude-opus-4-6")

  // Combine messages into a single prompt
  const parts: string[] = [];
  for (const msg of options.messages) {
    if (msg.role === 'system') {
      parts.push(`[System]\n${msg.content}`);
    } else if (msg.role === 'user') {
      parts.push(msg.content);
    }
  }
  const userMessage = parts.join('\n\n');

  // Step 1: StartCascade to get a server-registered cascade_id
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
  const serverCascadeId = (() => {
    const fields = parseProtoFields(startResult.data);
    const f1 = fields.find(f => f.fieldNum === 1 && f.data);
    return f1?.data?.toString('utf8') || cascadeId;
  })();

  // Step 2: Open streaming connection (envelope-framed Connect protocol)
  const streamProto = buildStreamReactiveUpdatesRequest(serverCascadeId);
  const streamEnvelope = Buffer.alloc(5 + streamProto.length);
  streamEnvelope.writeUInt32BE(streamProto.length, 1);
  streamProto.copy(streamEnvelope, 5);

  // Step 2b: Set up frame queue for incremental processing
  const frameQueue: Buffer[] = [];
  let streamDone = false;
  let resolveWait: (() => void) | null = null;

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
    throw new WindsurfError(
      `SendUserCascadeMessage failed: ${sendResult.data.toString('utf8')}`,
      WindsurfErrorCode.STREAM_ERROR
    );
  }

  // Step 4: Process frames incrementally, yielding text deltas as they arrive
  let phase: 'pre-user' | 'pre-bot' | 'response' | 'done' = 'pre-user';
  let previousText = '';
  let frameIdx = 0;

  while (!streamDone || frameIdx < frameQueue.length) {
    // Wait for new frames
    if (frameIdx >= frameQueue.length && !streamDone) {
      await new Promise<void>((r) => { resolveWait = r; });
      resolveWait = null;
    }

    // Process new frames
    while (frameIdx < frameQueue.length) {
      const frame = frameQueue[frameIdx++];
      const frameStr = frame.toString('utf8');

      if (phase === 'pre-user') {
        if (frameStr.includes(userMessage.substring(0, Math.min(20, userMessage.length)))) {
          phase = 'pre-bot';
        }
        continue;
      }

      if (phase === 'pre-bot') {
        if (frameStr.includes('bot-')) {
          phase = 'response';
          const texts = extractContentFromReactiveUpdate(frame);
          for (const t of texts) {
            if (t.length > previousText.length) {
              const delta = t.substring(previousText.length);
              if (delta) yield delta;
              previousText = t;
            }
          }
        }
        continue;
      }

      if (phase === 'response') {
        if (frameStr.includes('Response Statistics')) {
          phase = 'done';
          streamDone = true;
          break;
        }
        // Extract growing text and yield delta
        const texts = frameStr.includes('bot-')
          ? extractContentFromReactiveUpdate(frame)
          : extractAllF15Strings(frame);
        for (const t of texts) {
          if (t.length > previousText.length) {
            const delta = t.substring(previousText.length);
            if (delta) yield delta;
            previousText = t;
          }
        }
      }

      if (streamDone) break;
    }

    if (phase === 'done') break;
  }

  try { streamReq.destroy(); } catch {}
}

/**
 * Check if a model requires the Cascade protocol (no protobuf enum).
 */
export function requiresCascadeProtocol(enumValue: number): boolean {
  return enumValue === 0; // MODEL_UNSPECIFIED means enum-less model
}
