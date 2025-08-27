import { DurableObject } from "cloudflare:workers";
import { connect } from "cloudflare:sockets";

const textDecoder = new TextDecoder();
const isValidUUID = (uuid) => /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);

function uuidStringToUint8Array(uuid) {
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

function splitHostPort(address) {
	const str = String(address).trim();

	// ---------- 1️⃣ IPv6（方括号包裹） ----------
	// 形如 "[IPv6]" 或 "[IPv6]:port"
	if (str.startsWith('[')) {
		const endBracket = str.indexOf(']');
		if (endBracket !== -1) {                 			 // 找到匹配的 ']'
			const host = str.slice(0, endBracket + 1);
			const after = str.slice(endBracket + 1);     // 可能是 ":port" 或空
			const port = after.startsWith(':') ? Number(after.slice(1)) : 443;
			return { host, port };
		}
	}

	// ---------- 2️⃣ 其它形式： host[:port]（IPv4、域名、裸 IPv6 都走这里） ----------
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

	// ---------- 3️⃣ 没有端口的普通情况 ----------
	return { host: str, port: 443 };
}

/* ---------- 业务核心：解析自定义协议 ---------- */
async function parseSselvHeader(buffer, userIDUint8Array) {
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
		address = `${view[pos++]}.${view[pos++]}.${view[pos++]}.${view[pos++]}`;
	} else if (addrType === 2) {
		const len = view[pos++];
		address = textDecoder.decode(view.subarray(pos, pos + len));
		pos += len;
	} else if (addrType === 3) {
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
		// 某协议，固定的响应头数据
		responseHeader: new Uint8Array([view[0], 0]),
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
					if (ws.readyState !== WebSocket.OPEN) {
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
			safeCloseWebSocket(ws);
		});

	// 若目标服务器根本没有返回数据，尝试走代理（走 retry 逻辑）
	if (!hasIncoming && retry) {
		log && log("no data from remote, retrying via proxy");
		retry();
	}
}

/* ---------- 建立 TCP 连接（或走代理） ---------- */
async function handleTCPOutBound(
	remoteSocketWrapper,
	addressRemote,
	portRemote,
	rawClientData,
	ws,
	responseHeader,
	log,
	proxyInfo
) {
	// 统一的连接函数，返回一个 `TcpSocket`（cloudflare:sockets）
	async function connectAndWrite(host, port) {
		const tcp = connect({ hostname: host, port });
		remoteSocketWrapper.value = tcp;
		log(`connected to ${host}:${port}`);
		const writer = tcp.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcp;
	}

	// 代理重试：如果直连失败会走 proxy（proxyInfo 指的是 env.PYIP）
	async function retry() {
		const { hostname, port } = proxyInfo;
		const tcp = await connectAndWrite(hostname, port);
		tcp.closed.catch(() => { }).finally(() => safeCloseWebSocket(ws));
		remoteSocketToWS(tcp, ws, null, responseHeader, log);
	}

	// 1️⃣ 先尝试直连
	const tcp = await connectAndWrite(addressRemote, portRemote);
	// 2️⃣ 再把读写流桥接
	remoteSocketToWS(tcp, ws, retry, responseHeader, log);
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
	 * @param {{PYIP?:string, UUID4?:string}} env
	 */
	constructor(state, env) {
		super(state, env);
		this.state = state;
		this.proxyAddress = env.PYIP || "";
		this.defaultUserID = env.UUID4 || "c3deb827-585e-4137-98a4-2dd4058f9836";
	}

	/**
	 * 这里是 WebSocket 握手入口，等价于 `handleWebSocket(request)`.
	 * 只要收到 Upgrade: websocket，就返回 101 + clientSide WebSocket。
	 *
	 * @param {Request} request
	 * @returns {Promise<Response>}
	 */
	async fetch(request) {
		if (request.headers.get("Upgrade") !== "websocket") {
			return new Response("Only WebSocket is supported", { status: 400 });
		}

		// ----------------- 读取运行时配置 -----------------
		// 这里可以让每个实例拥有自己的 UUID、PROXYIP，也可以从 request 参数里动态覆盖
		const uuidFromEnv = this.defaultUserID;
		const uuidHeader = request.headers.get("x-uuid") || "";
		const uuidStr = uuidHeader || uuidFromEnv;
		if (!uuidStr || !isValidUUID(uuidStr)) {
			return new Response("Invalid or missing UUID", { status: 400 });
		}
		const userIDUint8Array = uuidStringToUint8Array(uuidStr);

		const url = new URL(request.url);
		const pathname = url.pathname;
		let pxyAddr = this.proxyAddress;
		if (pathname.includes("/pyip=")) {
			let pyipPath = pathname.split('/pyip=')[1];
			let trimPyip = pyipPath.trim();
			if (trimPyip) pxyAddr = trimPyip;
		}
		const hostPort = splitHostPort(pxyAddr);
		const proxyInfo = hostPort.host ? { hostname: hostPort.host, port: hostPort.port } : null; // 若未配置，则只走直连

		// ----------------- 真实的 WebSocket 处理 -----------------
		const wsPair = new WebSocketPair();
		const [clientSide, serverSide] = [wsPair[0], wsPair[1]];
		serverSide.accept();

		// 日志统一函数，便于在 DO 里打印
		let address = "";
		let portLog = "";
		const log = (msg, data) => {
			console.log(`[${address}:${portLog}] ${msg}`, data || "");
		};

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
					async write(chunk) {
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
						const {
							hasError,
							message,
							addressRemote = "",
							portRemote = 443,
							rawClientData,
							responseHeader,
						} = await parseSselvHeader(chunk, userIDUint8Array);
						address = addressRemote;
						portLog = `${portRemote}-${(Math.random().toString(36) + "0000").slice(2, 6)} tcp`;

						if (hasError) {
							throw new Error(message);
						}

						// ----- 真正建立 TCP（或代理） -----
						await handleTCPOutBound(
							remoteSocketWrapper,
							addressRemote,
							portRemote,
							rawClientData,
							serverSide,
							responseHeader,
							log,
							proxyInfo
						);
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
	 * @param {{PYIP?:string, UUID4?:string, WS_DO: DurableObjectNamespace}} env
	 * @param {ExecutionContext} ctx
	 */
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		// --------- 非 WebSocket 请求 ----------
		if (request.headers.get("Upgrade") !== "websocket") {
			if (url.pathname === "/") {
				return new Response(JSON.stringify(request.cf), { status: 200 });
			}
			return new Response("404 Not Found", { status: 404 });
		}

		// --------- WebSocket 握手：把完整 Request 转发给 Durable Object ----------
		const id = env.WS_DO.idFromName("ws");
		// https://developers.cloudflare.com/durable-objects/reference/data-location/#supported-locations-1
		const stub = env.WS_DO.get(id, { locationHint: "wnam" });

		return await stub.fetch(request);
	},
};
