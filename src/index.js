import { DurableObject } from "cloudflare:workers";
import { connect } from "cloudflare:sockets";

const textDecoder = new TextDecoder();

// WebSocket readyState 常量
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// DNS over HTTPS 服务地址
const DOH_SERVER = 'https://1.1.1.1/dns-query';

/* ---------- UUID / Base64 工具函数 ---------- */

function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

function userIdToUint8Array(uuid) {
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

/* ---------- host:port 解析 ---------- */

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

/* ---------- VLESS 协议头解析 ---------- */
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

	// 命令类型：1=TCP, 2=UDP
	const command = view[18 + optLength];
	const isUDP = command === 2;

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
		isUDP,
	};
}

/* ---------- 读取 WebSocket 为 ReadableStream ---------- */
function makeReadableWebSocketStream(ws, earlyDataHeader, log) {
	let cancelled = false;
	const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
	const stream = new ReadableStream({
		start(controller) {
			ws.addEventListener("message", (e) => {
				if (cancelled) return;
				controller.enqueue(e.data);
			});
			ws.addEventListener("close", () => {
				if (!cancelled) controller.close();
			});
			ws.addEventListener("error", (e) => {
				controller.error(e);
			});
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},
		cancel(reason) {
			cancelled = true;
			log(`readableStream canceled: ${reason}`);
			safeCloseWebSocket(ws);
		},
	});
	return stream;
}

/* ---------- 将 TCP Socket 数据写回 WebSocket ---------- */
async function remoteSocketToWS(remoteSocket, ws, retry, responseHeader = null, log = null) {
	let hasIncoming = false;
	let firstChunk = responseHeader instanceof Uint8Array && responseHeader.length > 0;

	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				async write(chunk, controller) {
					hasIncoming = true;
					if (ws.readyState !== WS_READY_STATE_OPEN) {
						controller.error("WebSocket not open");
						return;
					}
					let payload = chunk;
					if (firstChunk) {
						payload = new Uint8Array(responseHeader.length + chunk.length);
						payload.set(responseHeader, 0);
						payload.set(chunk, responseHeader.length);
						firstChunk = false;
					}
					ws.send(payload);
				},
				close() {
					log && log(`remoteSocket readable closed, hasIncoming=${hasIncoming}`);
				},
				abort(reason) {
					console.error("remoteSocket readable abort", reason);
				},
			})
		)
		.catch((e) => {
			console.error("remoteSocketToWS error:", e);
			// 还有 retry 机会时不关闭 WebSocket
			if (!retry) {
				safeCloseWebSocket(ws);
			}
		});

	// 若目标服务器根本没有返回数据，尝试走代理（走 retry 逻辑）
	if (!hasIncoming && retry) {
		log && log("no data from remote, retrying via proxy");
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
		if (!proxyInfo) return;
		const { hostname, port } = proxyInfo;
		const tcp = await connectAndWrite(hostname, port);
		tcp.closed.catch(() => { }).finally(() => safeCloseWebSocket(ws));
		remoteSocketToWS(tcp, ws, null, headerInfo?.responseHeader, log);
	}

	// 1、先尝试直连
	const tcp = await connectAndWrite(headerInfo?.addressRemote, headerInfo?.portRemote);
	// 2、再把读写流桥接
	remoteSocketToWS(tcp, ws, retry, headerInfo?.responseHeader, log);
}

/* ---------- UDP DNS 代理（端口 53 → DoH） ---------- */
async function handleUDPOutBound(webSocket, responseHeader, log) {
	let isHeaderSent = false;
	let buffer = new Uint8Array(0);

	const transformStream = new TransformStream({
		transform(chunk, controller) {
			// 将新 chunk 追加到 buffer
			const newBuf = new Uint8Array(buffer.byteLength + chunk.byteLength);
			newBuf.set(buffer, 0);
			newBuf.set(new Uint8Array(chunk), buffer.byteLength);
			buffer = newBuf;

			// 循环提取完整的 UDP 包：[2字节长度][数据]
			while (buffer.byteLength >= 2) {
				const udpPacketLength = new DataView(buffer.buffer, buffer.byteOffset, 2).getUint16(0);
				if (buffer.byteLength < 2 + udpPacketLength) {
					break; // 数据不完整，等待下一个 chunk
				}
				const udpData = new Uint8Array(buffer.slice(2, 2 + udpPacketLength));
				controller.enqueue(udpData);
				buffer = buffer.slice(2 + udpPacketLength);
			}
		},
	});

	// 只处理 DNS UDP（端口 53）
	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch(DOH_SERVER, {
				method: 'POST',
				headers: { 'content-type': 'application/dns-message' },
				body: chunk,
			});
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				log(`doh success and dns message length is ${udpSize}`);
				if (isHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		log('dns udp has error' + error);
	});

	const writer = transformStream.writable.getWriter();

	return {
		/**
		 * @param {Uint8Array} chunk
		 */
		write(chunk) {
			writer.write(chunk);
		}
	};
}

/* ---------- 安全关闭 WebSocket ---------- */
function safeCloseWebSocket(ws, code = 1000, reason = "Normal Closure") {
	try {
		if (ws.readyState === WS_READY_STATE_OPEN || ws.readyState === WS_READY_STATE_CLOSING) {
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
	 * @param {{PYIP?:string, UUID4?:string}} env
	 */
	constructor(state, env) {
		super(state, env);
		this.state = state;
		this.proxyAddress = env.PYIP ?? "";
		this.uuid4 = env.UUID4 ?? "c3deb827-585e-4137-98a4-2dd4058f9836";
		this.userIDUint8Array = userIdToUint8Array(this.uuid4);
	}

	/**
	 * @param {Request} request
	 * @returns {Promise<Response>}
	 */
	async fetch(request) {
		// ----------------- 非 WebSocket 请求 ----------
		if (request.headers.get("Upgrade") !== "websocket") {
			const url = new URL(request.url);
			if (url.pathname === "/" || url.pathname === "/cf") {
				return new Response(JSON.stringify(request.cf), { status: 200 });
			}
			return new Response("Not found", { status: 404 });
		}

		// ----------------- 读取运行时配置 -----------------
		const userIDUint8Array = this.userIDUint8Array;

		const hostPort = splitHostPort(this.proxyAddress);
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

		// ---------- 用一个 wrapper 保存 "远程 TCP socket" ----------
		const remoteSocketWrapper = { value: null };
		let udpWrite = null;
		let isDns = false;

		// ---------- 把 inbound 流 pipe 到处理函数 ----------
		inbound
			.pipeTo(
				new WritableStream({
					async write(chunk, controller) {
						// DNS UDP 已建立，直接转发 DNS 数据
						if (isDns && udpWrite) {
							return udpWrite(chunk);
						}
						// TCP 连接已建立，直接转发
						if (remoteSocketWrapper.value) {
							const writer = remoteSocketWrapper.value.writable.getWriter();
							await writer.write(chunk);
							writer.releaseLock();
							return;
						}

						// ----- 解析 VLESS 协议头，得到目标地址、端口、以及原始客户端数据 -----
						let headerInfo = parseSse1vHeader(chunk, userIDUint8Array);
						if (!headerInfo || headerInfo?.hasError) {
							throw new Error(`VLESS header parse error: ${headerInfo?.message}`);
						}

						address = headerInfo?.addressRemote;
						portLog = `-${(Math.random().toString(36) + "000000").slice(2, 8)} ${headerInfo?.isUDP ? 'udp' : 'tcp'}`;

						// UDP 仅允许端口 53（DNS）
						if (headerInfo?.isUDP) {
							if (headerInfo?.portRemote === 53) {
								isDns = true;
								const { write } = await handleUDPOutBound(serverSide, headerInfo?.responseHeader, log);
								udpWrite = write;
								udpWrite(headerInfo?.rawClientData);
								return;
							} else {
								throw new Error("UDP proxy only enable for DNS which is port 53");
							}
						}

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
	 * @param {{PYIP?:string, UUID4?:string, REGION?:string, WS_DO: DurableObjectNamespace}} env
	 * @param {ExecutionContext} ctx
	 */
	async fetch(request, env, ctx) {
		// --------- 非 WebSocket 请求 ----------
		if (request.headers.get("Upgrade") !== "websocket") {
			const url = new URL(request.url);
			if (url.pathname === "/" || url.pathname === "/cf") {
				return new Response(JSON.stringify(request.cf), { status: 200 });
			}
			return new Response("Not found", { status: 404 });
		}

		// --------- WebSocket 请求：把完整 Request 转发给 Durable Object ----------
		// https://developers.cloudflare.com/durable-objects/reference/data-location/#supported-locations-1
		// https://where.durableobjects.live/
		// 可选：["wnam", "enam", "sam", "weur", "eeur", "apac", "oc", "afr", "me"]
		const doLocation = env.REGION || "wnam";
		const name = `user-${doLocation}-${env.UUID4 ?? "c3deb827-585e-4137-98a4-2dd4058f9836"}`;
		const id = env.WS_DO.idFromName(name);
		const stub = env.WS_DO.get(id, { locationHint: doLocation });

		return await stub.fetch(request);
	},
};
