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
// Response Extraction
// ============================================================================

/** Metadata/noise patterns to exclude from extracted text */
const NOISE_PATTERNS = [
  /^file:\/\//,
  /^ssh:\/\//,
  /^\/Applications\//,
  /^\/Users\//,
  /^\{"file_path"/,
  /^\{"DirectoryPath"/,
  /^\{"command"/,
  /^Credits spent/,
  /^trafficType$/,
  /^Response Statistics$/,
  /^ON_DEMAND$/,
  /^responseId$/,
  /^MODEL_/,
  /^claude-opus/,
  /^claude-sonnet/,
  /^windsurf$/,
  /^[a-f0-9-]{36}$/,
];

/** Patterns that indicate Cascade system prompt / internal config (not user content) */
const SYSTEM_PROMPT_MARKERS = [
  '<communication_style>',
  '<tool_calling>',
  '<making_code_changes>',
  '<workspace_information>',
  '<workspace_layout',
  '<memory_system>',
  '<user_information>',
  '<ide_metadata>',
  'You are Cascade, a powerful agentic AI',
  'STRICT OUTPUT:',
  'RESPONSE FORMAT:',
  '<existing_code>',
  '<citation_guidelines>',
];

/**
 * Extract the longest natural-language text from a raw protobuf frame.
 *
 * Instead of navigating protobuf field paths (which is fragile due to
 * nested tool calls and metadata at the same field numbers), we scan
 * for the longest contiguous printable substring containing spaces.
 * The assistant's text response is always the longest such string.
 */
function extractLongestNaturalText(buffer: Buffer): string {
  const str = buffer.toString('utf8');
  // Find all runs of printable characters (including newlines) ≥ 20 chars
  const matches = [...str.matchAll(/[\x20-\x7e\n\r\t]{20,}/g)];

  let best = '';
  for (const m of matches) {
    const candidate = m[0];
    // Must contain spaces (natural language, not identifiers)
    if (!candidate.includes(' ')) continue;
    if (candidate.length <= best.length) continue;
    // Skip metadata noise
    if (NOISE_PATTERNS.some(p => p.test(candidate))) continue;
    // Skip Cascade system prompt / internal config
    if (SYSTEM_PROMPT_MARKERS.some(m => candidate.includes(m))) continue;
    best = candidate;
  }

  // Clean up: remove leading protobuf tag bytes (e.g., "z8\n" prefix)
  best = best.replace(/^z.\n?/, '').replace(/^z.\r?\n?/, '').trim();
  // Remove trailing protobuf artifacts
  best = best.replace(/\n?\*?\s*$/, '').trim();

  return best;
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

  // Only send user messages — Cascade has its own system prompt.
  // Sending OpenCode's system prompt would leak it into the response.
  const parts: string[] = [];
  for (const msg of options.messages) {
    if (msg.role === 'user') {
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
  // Extract cascade_id (field 1 string) from StartCascadeResponse
  const serverCascadeId = (() => {
    const data = startResult.data;
    if (data.length < 3) return cascadeId;
    // Field 1, wire type 2: tag byte = 0x0a, then varint length, then string
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
    return cascadeId;
  })();

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
          idleTimer = setTimeout(() => { streamDone = true; resolveWait?.(); }, 5000);
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

  // Extract text from the LAST few frames only.
  // The Cascade stream structure: config frames → user echo → tool calls → response.
  // The actual assistant response is always in the last frames before the stream settles.
  // Early frames contain system prompts, tool definitions, and config — skip them all.
  const lastN = Math.min(5, frameQueue.length);
  let bestResponse = '';

  for (let i = frameQueue.length - lastN; i < frameQueue.length; i++) {
    const text = extractLongestNaturalText(frameQueue[i]);
    if (text.length > bestResponse.length) {
      bestResponse = text;
    }
  }

  if (bestResponse) {
    yield bestResponse;
  }
}

/**
 * Check if a model requires the Cascade protocol (no protobuf enum).
 */
export function requiresCascadeProtocol(enumValue: number): boolean {
  return enumValue === 0; // MODEL_UNSPECIFIED means enum-less model
}
