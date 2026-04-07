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
 * Recursively find all field-15 string values in a protobuf buffer.
 *
 * In the Cascade reactive update stream, field 15 at the deepest message
 * nesting contains the assistant's response text chunks. We collect all
 * f15 strings that aren't metadata (model names, UUIDs, paths, etc).
 */
function extractContentFromReactiveUpdate(buffer: Buffer): string[] {
  const texts: string[] = [];

  function walk(buf: Buffer): void {
    const fields = parseProtoFields(buf);
    for (const f of fields) {
      if (f.wireType !== 2 || !f.data) continue;
      const data = f.data;
      const str = data.toString('utf8');
      const isPrintable = data.length > 0 && /^[\x20-\x7e\n\r\t\u00a0-\uffff]+$/.test(str);

      if (f.fieldNum === 15 && isPrintable) {
        // Field 15 at any depth = potential content text
        // Filter metadata noise
        if (
          !/^[a-f0-9-]{10,}$/.test(str) &&
          !/^MODEL_/.test(str) &&
          !/^claude-/.test(str) &&
          !/^\//.test(str) &&
          !/^windsurf$/i.test(str) &&
          !/^[0-9.]+$/.test(str) &&
          !/^(Response Statistics|Credits spent|credits?|model|Model| credits?|yaml)$/i.test(str) &&
          !/^Claude (Opus|Sonnet|Haiku|Code)/.test(str)
        ) {
          texts.push(str);
        }
      } else if (!isPrintable && data.length > 2) {
        // Recurse into nested messages
        walk(data);
      }
    }
  }

  walk(buffer);
  return texts;
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

  const streamPromise = new Promise<Buffer[]>((resolve, reject) => {
    const chunks: Buffer[] = [];
    const req = http.request(
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
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => resolve(chunks));
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    req.write(streamEnvelope);
    req.end();
    setTimeout(() => { req.destroy(); resolve(chunks); }, 120000);
  });

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

  // Step 4: Wait for streaming response
  const responseChunks = await streamPromise;
  const fullResponse = Buffer.concat(responseChunks);
  if (fullResponse.length === 0) {
    throw new WindsurfError(
      'Empty response from Cascade stream',
      WindsurfErrorCode.STREAM_ERROR
    );
  }

  // Parse Connect protocol streaming response
  // Each chunk is envelope-framed: 1 byte flags + 4 bytes length + protobuf
  let offset = 0;
  const allTexts: string[] = [];

  while (offset + 5 <= fullResponse.length) {
    const flags = fullResponse[offset];
    const msgLen = fullResponse.readUInt32BE(offset + 1);
    offset += 5;

    if (offset + msgLen > fullResponse.length) break;

    if (flags === 2) break; // End-of-stream

    const msgData = fullResponse.subarray(offset, offset + msgLen);
    const texts = extractContentFromReactiveUpdate(msgData);
    allTexts.push(...texts);
    offset += msgLen;
  }

  // Fallback: try raw protobuf if Connect framing didn't match
  if (allTexts.length === 0) {
    const texts = extractContentFromReactiveUpdate(fullResponse);
    allTexts.push(...texts);
  }

  if (allTexts.length > 0) {
    yield allTexts.join('');
  }
}

/**
 * Check if a model requires the Cascade protocol (no protobuf enum).
 */
export function requiresCascadeProtocol(enumValue: number): boolean {
  return enumValue === 0; // MODEL_UNSPECIFIED means enum-less model
}
