import { DurableObject } from "cloudflare:workers";
import { connect } from "cloudflare:sockets";

const textDecoder = new TextDecoder();
const TRUE_VALUES = new Set(["true", "1", "yes", "on"]);
const urls = [
	'https://www.bilibili.com',
	'https://www.nicovideo.jp',
	'https://tv.naver.com',
	'https://www.hotstar.com',
	'https://www.netflix.com',
	'https://www.dailymotion.com',
	'https://www.youtube.com',
	'https://www.hulu.com',
	'https://fmovies.llc',
	'https://hdtodayz.to',
	'https://radar.cloudflare.com',
];

function boolEnv(value, defaultValue = false) {
	if (value == null) return defaultValue;
	if (typeof value === "boolean") return value;
	const normalized = String(value).trim().toLowerCase();
	return TRUE_VALUES.has(normalized);
}

function userIdToUint8Array(uuid) {
	const isValidUUID = (uuid) => /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
	if (!uuid || !isValidUUID(uuid)) throw new Error("Invalid UUID format");
	const hex = uuid.replace(/-/g, "");
	if (hex.length !== 32) throw new Error("Invalid UUID format");
	const arr = new Uint8Array(16);
	for (let i = 0; i < 16; ++i) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
	return arr;
}

function base64ToArrayBuffer(base64Str) {
	if (!base64Str) return { error: null };
	try {
		base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
		const decoded = atob(base64Str);
		const arr = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
		return { earlyData: arr.buffer, error: null };
	} catch (e) {
		return { error: e };
	}
}

function sha224Encrypt(str) {
	if (typeof str !== 'string') throw new TypeError('sha224Encrypt: input must be a string');

	const K = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401,
		607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628,
		770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711,
		113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037,
		2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616,
		659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424,
		2428436474, 2756734187, 3204031479, 3329325298];
	const H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	function R(x, n) { return (x >>> n) | (x << (32 - n)); }
	const m = new TextEncoder().encode(str);
	const l = m.length * 8;
	const padLen = ((m.length + 9 + 63) >> 6) << 6;
	const buf = new Uint8Array(padLen);
	buf.set(m);
	buf[m.length] = 0x80;
	new DataView(buf.buffer).setUint32(buf.length - 4, l, false);
	const w = new Uint32Array(64), h = H.slice();
	for (let i = 0; i < buf.length; i += 64) {
		const view = new DataView(buf.buffer, i, 64);
		for (let j = 0; j < 16; j++) w[j] = view.getUint32(j * 4);
		for (let j = 16; j < 64; j++) {
			const s0 = R(w[j - 15], 7) ^ R(w[j - 15], 18) ^ (w[j - 15] >>> 3);
			const s1 = R(w[j - 2], 17) ^ R(w[j - 2], 19) ^ (w[j - 2] >>> 10);
			w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, hh] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = R(e, 6) ^ R(e, 11) ^ R(e, 25), ch = (e & f) ^ ((~e) & g);
			const temp1 = (hh + S1 + ch + K[j] + w[j]) >>> 0;
			const S0 = R(a, 2) ^ R(a, 13) ^ R(a, 22), maj = (a & b) ^ (a & c) ^ (b & c);
			const temp2 = (S0 + maj) >>> 0;
			[hh, g, f, e, d, c, b, a] = [g, f, e, (d + temp1) >>> 0, c, b, a, (temp1 + temp2) >>> 0];
		}
		h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0;
		h[3] = (h[3] + d) >>> 0; h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
		h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
	}

	return h.slice(0, 7).map(x => x.toString(16).padStart(8, '0')).join('');
}

function splitHostPort(address) {
	const str = String(address).trim();

	// ---------- IPv6：形如 "[IPv6]" 或 "[IPv6]:port" ----------
	if (str.startsWith('[')) {
		const endBracket = str.indexOf(']');
		if (endBracket !== -1) {
			const host = str.slice(0, endBracket + 1);   // 包含方括号
			const after = str.slice(endBracket + 1);     // 可能是 ":port" 或空端口
			const port = after.startsWith(':') ? Number(after.slice(1)) : 443;
			return { host, port };
		}
	}

	// ---------- 其它形式： host[:port]（IPv4、域名、裸 IPv6 都走这里） ----------
	// 使用 lastIndexOf，防止误把 IPv6 中的冒号算作端口（IPv6 已被 [] 包裹，不会走到这里）
	const colonIdx = str.lastIndexOf(':');
	if (colonIdx > -1) {
		const possiblePort = str.slice(colonIdx + 1);
		if (/^\d+$/.test(possiblePort)) {
			const host = str.slice(0, colonIdx);
			const port = Number(possiblePort);
			return { host, port };
		}
	}

	// ---------- 没有端口的普通情况 ----------
	return { host: str, port: 443 };
}


/* ---------- 业务核心：解析自定义协议 ---------- */
function parsedProtocolMapCode(buffer) {
	const view = new Uint8Array(buffer);

	// 检查 UUID（v4 或 v7） -> vless 协议
	if (view.byteLength >= 17) {
		const version = (view[7] & 0xf0) >> 4;
		const isRFC4122Variant = (view[9] & 0xc0) === 0x80;

		if (isRFC4122Variant && (version === 4 || version === 7)) {
			return 1;
		}
	}
	// 检查 trojan 定界符 -> trojan 协议
	if (view.byteLength >= 62) {
		const [b0, b1, b2, b3] = [view[56], view[57], view[58], view[59]];
		const validB2 = [0x01, 0x03, 0x7f];
		const validB3 = [0x01, 0x03, 0x04];

		if (b0 === 0x0d && b1 === 0x0a && validB2.includes(b2) && validB3.includes(b3)) {
			return 2;
		}
	}
	// 未加密的 ss 协议
	if (view.byteLength > 10) {
		const validB1 = [0x01, 0x03, 0x04];
		if (validB1.includes(view[0])) return 0;
	}

	return 3;
}

function parseSse1vHeader(buffer, userIDUint8Array) {
	if (!buffer || buffer.byteLength < 24) return { hasError: true, message: "Too short" };
	const view = new Uint8Array(buffer);
	// UUID 校验
	for (let i = 0; i < 16; ++i) {
		if (view[i + 1] !== userIDUint8Array[i]) {
			return { hasError: true, message: "Unauthorized UUID" };
		}
	}
	const optLength = view[17];
	let pos = 18 + optLength + 1;

	const port = (view[pos] << 8) | view[pos + 1];
	pos += 2;

	const addrType = view[pos++];
	let address = "";
	if (addrType === 1) {
		// IPv4
		address = `${view[pos++]}.${view[pos++]}.${view[pos++]}.${view[pos++]}`;
	} else if (addrType === 2) {
		// 域名
		const len = view[pos++];
		address = textDecoder.decode(view.subarray(pos, pos + len));
		pos += len;
	} else if (addrType === 3) {
		// IPv6
		const parts = [];
		for (let i = 0; i < 8; ++i, pos += 2) {
			parts.push(((view[pos] << 8) | view[pos + 1]).toString(16));
		}
		address = parts.join(":");
	} else {
		return { hasError: true, message: `Invalid address type ${addrType}` };
	}

	return {
		hasError: false,
		addressRemote: address,
		portRemote: port,
		rawClientData: buffer.slice(pos),
		addressType: addrType,
		responseHeader: new Uint8Array([view[0], 0]),
	};
}

function parseNaj0rtHeader(buffer, sha224Password) {
	const view = new Uint8Array(buffer);
	if (view.length < 56 + 2 + 1 + 1 + 2 + 2) return { hasError: true, message: 'Header too short' };

	// 校验明文密码
	const passStr = String.fromCharCode(...view.slice(0, 56));
	if (passStr !== sha224Password) return { hasError: true, message: 'Unauthorized password' };

	// 检查CRLF
	if (view[56] !== 0x0d || view[57] !== 0x0a) return { hasError: true, message: 'Missing CRLF after password hash' };

	let isUDP = false;
	let p = 58;

	const cmd = view[p++];
	if (cmd == 0x03) isUDP = true;
	else if (cmd !== 0x01 && cmd !== 0x03) return { hasError: true, message: `Unknown CMD: ${cmd}` };

	const addrType = view[p++];
	let address = '';
	if (addrType === 1) {
		// IPv4
		if (view.length < p + 4 + 2) return { hasError: true, message: 'Header too short for IPv4' };
		address = `${view[p++]}.${view[p++]}.${view[p++]}.${view[p++]}`;
	} else if (addrType === 3) {
		// 域名
		const len = view[p++];
		if (view.length < p + len + 2) return { hasError: true, message: 'Header too short for domain' };
		address = String.fromCharCode(...view.slice(p, p + len));
		p += len;
	} else if (addrType === 4) {
		// IPv6
		if (view.length < p + 16 + 2) return { hasError: true, message: 'Header too short for IPv6' };
		let parts = [];
		for (let i = 0; i < 8; ++i) {
			const part = (view[p++] << 8) | view[p++];
			parts.push(part.toString(16));
		}
		address = parts.join(':');
	} else {
		return { hasError: true, message: `Unknown addrType: ${addrType}` };
	}
	const port = (view[p++] << 8) | view[p++];

	return {
		hasError: false,
		addressRemote: address,
		portRemote: port,
		rawClientData: new Uint8Array(buffer, p + 2),
		addressType: addrType,
		responseHeader: null,
	};
}

function parseSkc0swodahsHeader(buffer) {
	const view = new DataView(buffer);
	const addrType = view.getUint8(0);
	let address = '',
		offset = 1;
	if (addrType === 1) {
		// IPv4
		address = Array.from(new Uint8Array(buffer.slice(1, 5))).join('.');
		offset = 5;
	} else if (addrType === 3) {
		// 域名
		const len = view.getUint8(1);
		address = textDecoder.decode(buffer.slice(2, 2 + len));
		offset = 2 + len;
	} else if (addrType === 4) {
		// IPv6
		const parts = [];
		for (let i = 0; i < 8; i++) parts.push(view.getUint16(1 + i * 2).toString(16));
		address = parts.join(':');
		offset = 17;
	} else {
		return { hasError: true, message: `Invalid addressType: ${addrType}` };
	}
	const port = new DataView(buffer.slice(offset, offset + 2)).getUint16(0);

	return {
		hasError: false,
		addressRemote: address,
		portRemote: port,
		rawClientData: buffer.slice(offset + 2),
		addressType: addrType,
		responseHeader: null,
	};
}

/* ---------- 读取 WebSocket 为 ReadableStream ---------- */
function makeReadableWebSocketStream(ws, earlyDataHeader, log) {
	let cancelled = false;
	let closed = false;
	const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
	let controller;
	// 缓存消息，无论 controller 是否准备好
	const messageQueue = [];
	function enqueueMessage(data) {
		if (controller && !closed && !cancelled) {
			try {
				controller.enqueue(data);
			} catch (err) {
				// enqueue失败，放回缓存
				log(`enqueue error: ${err}, caching message`);
				messageQueue.unshift(data); // 放回队首保证顺序
			}
		} else {
			messageQueue.push(data);
		}
	}
	function onMessage(e) {
		if (cancelled || closed) return;
		enqueueMessage(e.data);
	}
	function onClose() {
		if (cancelled || closed) return;
		closed = true;
		if (controller) {
			controller.close();
		}
	}
	function onError(e) {
		if (cancelled || closed) return;
		closed = true;
		if (controller) {
			controller.error(e);
		}
	}
	const removeListeners = () => {
		ws.removeEventListener('message', onMessage);
		ws.removeEventListener('close', onClose);
		ws.removeEventListener('error', onError);
	};
	const stream = new ReadableStream({
		start(ctrl) {
			controller = ctrl;
			if (error) {
				ctrl.error(error);
				return;
			}
			ws.addEventListener('message', onMessage);
			ws.addEventListener('close', onClose);
			ws.addEventListener('error', onError);
			// 先入队早期数据
			if (earlyData) {
				enqueueMessage(earlyData);
			}
			// 将缓存消息入队
			while (messageQueue.length > 0) {
				enqueueMessage(messageQueue.shift());
			}
		},
		pull(ctrl) {
			// WebSocket 是 push 模式，一般不需要在 pull 做操作
		},
		cancel(reason) {
			if (cancelled) return;
			cancelled = true;
			log(`readableStream canceled: ${reason}`);
			removeListeners();
			safeCloseWebSocket(ws);
			if (controller && !closed) {
				controller.close();
			}
		}
	});
	return stream;
}

/* ---------- 将 TCP Socket 数据写回 WebSocket ---------- */
async function remoteSocketToWS(remoteSocket, ws, retry, responseHeader = null, log = null) {
	let hasIncoming = false;
	// 构造 payload 拼接器（首块拼接 responseHeader）
	let buildPayload = (chunk) => chunk;
	if (responseHeader instanceof Uint8Array && responseHeader.length > 0) {
		buildPayload = (chunk) => {
			const payload = new Uint8Array(responseHeader.length + chunk.length);
			payload.set(responseHeader, 0);
			payload.set(chunk, responseHeader.length);
			// 用完一次后恢复直传
			buildPayload = (c) => c;
			return payload;
		};
	}
	// 自适应 backpressure 控制
	async function waitForBackpressure(ws) {
		const buffered = ws.bufferedAmount;

		if (buffered < 256 * 1024) {
			// 小于 256KB，不等待
			return;
		}
		// 每 1MB 等待 2ms，上限 50ms
		const waitMs = Math.min(50, Math.ceil(buffered / (1024 * 1024)) * 2);
		log?.(`backpressure: buffered=${buffered} bytes, wait ${waitMs}ms`);
		await new Promise(r => setTimeout(r, waitMs));
	}
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				async write(chunk) {
					hasIncoming = true;
					if (ws.readyState !== WebSocket.OPEN) {
						log?.("WebSocket not open, closing");
						safeCloseWebSocket(ws);
						return;
					}
					const payload = buildPayload(chunk);
					// backpressure 控制
					await waitForBackpressure(ws);
					ws.send(payload);
				},
				close() {
					log?.(`remoteSocket closed, hasIncoming=${hasIncoming}`);
				},
				abort(reason) {
					log?.(`remoteSocket aborted: ${reason}`);
				},
			})
		)
		.catch((e) => {
			log?.(`remoteSocketToWS error: ${e}`);
			safeCloseWebSocket(ws);
		});

	if (!hasIncoming && retry) {
		log?.("no data from remote, retrying via proxy");
		retry();
	}
}

/* ---------- 建立 TCP 连接（或走代理） ---------- */
async function handleTCPOutBound(remoteSocketWrapper, headerInfo, proxyInfo, ws, log) {
	// 统一的连接函数，返回一个 `TcpSocket`（cloudflare:sockets）
	async function connectAndWrite(host, port) {
		const tcp = connect({ hostname: host, port });
		remoteSocketWrapper.value = tcp;
		log(`connected to ${host}:${port}`);
		const writer = tcp.writable.getWriter();
		await writer.write(headerInfo?.rawClientData);
		writer.releaseLock();
		return tcp;
	}

	// 代理重试：如果直连失败会走 proxy（proxyInfo 是 env.PYIP 分割出来的 hostname 和 port ）
	async function retry() {
		const { hostname, port } = proxyInfo;
		const tcp = await connectAndWrite(hostname, port);
		tcp.closed.catch(() => { }).finally(() => safeCloseWebSocket(ws));
		remoteSocketToWS(tcp, ws, null, headerInfo?.responseHeader, log);
	}

	// 1️⃣ 先尝试直连
	const tcp = await connectAndWrite(headerInfo?.addressRemote, headerInfo?.portRemote);
	// 2️⃣ 再把读写流桥接
	remoteSocketToWS(tcp, ws, retry, headerInfo?.responseHeader, log);
}

/* ---------- 安全关闭 WebSocket ---------- */
function safeCloseWebSocket(ws, code = 1000, reason = "Normal Closure") {
	try {
		if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
			ws.close(code, reason);
		}
	} catch (e) {
		console.error("Failed to close WebSocket", e);
	}
}

/* ------------------- Durable Object 本体 ------------------- */
export class WsDo extends DurableObject {
	/**
	 * @param {DurableObjectState} state
	 * @param {{PYIP?:string, UUID4?:string, PASSWORD?:string, ENABLE_SS?:string|boolean}} env
	 */
	constructor(state, env) {
		super(state, env);
		this.state = state;
		this.proxyAddress = env.PYIP ?? "";
		this.uuid4 = env.UUID4 ?? "c3deb827-585e-4137-98a4-2dd4058f9836";
		this.userIDUint8Array = userIdToUint8Array(this.uuid4);
		this.sha224Password = sha224Encrypt(env.PASSWORD ?? this.uuid4);
		this.ssEnable = boolEnv(env.ENABLE_SS);
	}

	/**
	 * @param {Request} request
	 * @returns {Promise<Response>}
	 */
	async fetch(request) {
		if (request.headers.get("Upgrade") !== "websocket") {
			return new Response("Only WebSocket is supported", { status: 400 });
		}

		// ----------------- 读取运行时配置 -----------------
		const userIDUint8Array = this.userIDUint8Array;
		const sha224Password = this.sha224Password;
		const ssEnable = this.ssEnable;

		// PROXYIP 支持动态覆盖
		let pxyAddr = this.proxyAddress;
		const url = new URL(request.url);
		const pathname = url.pathname;
		if (pathname.includes("/pyip=")) {
			let pyipPath = pathname.split('/pyip=')[1];
			let trimPyip = pyipPath.trim();
			if (trimPyip) pxyAddr = trimPyip;
		}
		const hostPort = splitHostPort(pxyAddr);
		const proxyInfo = hostPort.host ? { hostname: hostPort.host, port: hostPort.port } : null;

		// ----------------- 真实的 WebSocket 处理 -----------------
		const [clientSide, serverSide] = Object.values(new WebSocketPair());
		serverSide.accept();

		// 日志统一函数，便于在 DO 里打印
		let address = "";
		let portLog = "";
		const log = (msg, data) => console.log(`[${address}${portLog}] ${msg}`, data || "");

		// ---------- 将浏览器→DO 的数据转成可读流 ----------
		const earlyProtoHeader = request.headers.get("sec-websocket-protocol") || "";
		const inbound = makeReadableWebSocketStream(serverSide, earlyProtoHeader, log);

		// ---------- 用一个 wrapper 保存 “远程 TCP socket” ----------
		const remoteSocketWrapper = { value: null };
		let udpWrite = null; // 暂时不实现

		// ---------- 把 inbound 流 pipe 到处理函数 ----------
		inbound
			.pipeTo(
				new WritableStream({
					async write(chunk, controller) {
						if (udpWrite) {
							return udpWrite(chunk);
						}
						if (remoteSocketWrapper.value) {
							// 已经建立了 TCP，直接转发
							const writer = remoteSocketWrapper.value.writable.getWriter();
							await writer.write(chunk);
							writer.releaseLock();
							return;
						}

						// ----- 解析协议头，得到目标地址、端口、以及原始客户端数据 -----
						let mapCode = parsedProtocolMapCode(chunk);
						const parseHandlers = {
							...(ssEnable ? { 0: [parseSkc0swodahsHeader, [chunk]] } : {}),
							1: [parseSse1vHeader, [chunk, userIDUint8Array]],
							2: [parseNaj0rtHeader, [chunk, sha224Password]],
						};
						const entry = parseHandlers[mapCode];
						if (!entry) return log(`Unsupported protocol map code: ${mapCode}`);
						const [handlerFn, args] = entry;
						let headerInfo = handlerFn(...args);
						if (!headerInfo || headerInfo?.hasError) return controller.error(`Header parse error: ${headerInfo?.message}`);

						address = headerInfo?.addressRemote;
						portLog = `-${(Math.random().toString(36) + "000000").slice(2, 8)} tcp`;

						// ----- 真正建立 TCP（或代理） -----
						await handleTCPOutBound(remoteSocketWrapper, headerInfo, proxyInfo, serverSide, log);
					},
					close() {
						log("inbound stream closed");
					},
					abort(reason) {
						log("inbound stream aborted", reason);
					},
				})
			)
			.catch((e) => {
				log("inbound pipe error", e);
			});

		// 最终把 clientSide 交给浏览器
		return new Response(null, { status: 101, webSocket: clientSide });
	}
}

export default {
	/**
	 * @param {Request} request
	 * @param {{PYIP?:string, UUID4?:string, PASSWORD?:string, ENABLE_SS?:string|boolean, WS_DO: DurableObjectNamespace}} env
	 * @param {ExecutionContext} ctx
	 */
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const pathname = url.pathname;

		// --------- 非 WebSocket 请求 ----------
		if (request.headers.get("Upgrade") !== "websocket") {
			if (pathname === "/") {
				const redirectUrl = urls[Math.floor(Math.random() * urls.length)];
				return Response.redirect(redirectUrl, 301);
			} else if (pathname === "/cf") {
				return new Response(JSON.stringify(request.cf), { status: 200 });
			}
			return new Response("404 Not Found", { status: 404 });
		}

		// --------- WebSocket 握手：把完整 Request 转发给 Durable Object ----------
		const name = `user-${env.UUID4 ?? "c3deb827-585e-4137-98a4-2dd4058f9836"}`;
		const id = env.WS_DO.idFromName(name);
		// https://developers.cloudflare.com/durable-objects/reference/data-location/#supported-locations-1
		const stub = env.WS_DO.get(id, { locationHint: "wnam" });

		return await stub.fetch(request);
	},
};
