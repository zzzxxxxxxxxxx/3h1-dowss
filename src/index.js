import { DurableObject } from "cloudflare:workers";
import { connect } from "cloudflare:sockets";

const textDecoder = new TextDecoder();
const URLS = [
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

function splitHostPort(address) {
	const str = String(address).trim();
	if (str.startsWith('[')) {
		const endBracket = str.indexOf(']');
		if (endBracket !== -1) {
			const host = str.slice(0, endBracket + 1);
			const after = str.slice(endBracket + 1);
			const port = after.startsWith(':') ? Number(after.slice(1)) : 443;
			return { host, port };
		}
	}
	const colonIdx = str.lastIndexOf(':');
	if (colonIdx > -1) {
		const possiblePort = str.slice(colonIdx + 1);
		if (/^\d+$/.test(possiblePort)) {
			const host = str.slice(0, colonIdx);
			const port = Number(possiblePort);
			return { host, port };
		}
	}
	return { host: str, port: 443 };
}

function parseSse1vHeader(buffer, userIDUint8Array) {
	if (!buffer || buffer.byteLength < 24) return { hasError: true, message: "Too short" };
	const view = new Uint8Array(buffer);
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
		responseHeader: new Uint8Array([view[0], 0]),
	};
}

function makeReadableWebSocketStream(ws, earlyDataHeader, log) {
	let cancelled = false;
	const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
	return new ReadableStream({
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
}

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
	if (!hasIncoming && retry) {
		log && log("no data from remote, retrying via proxy");
		retry();
	}
}

async function handleTCPOutBound(remoteSocketWrapper, headerInfo, proxyInfo, ws, log) {
	async function connectAndWrite(host, port) {
		const tcp = connect({ hostname: host, port });
		remoteSocketWrapper.value = tcp;
		log(`connected to ${host}:${port}`);
		const writer = tcp.writable.getWriter();
		await writer.write(headerInfo?.rawClientData);
		remoteSocketWrapper.writer = writer;
		return tcp;
	}
	async function retry() {
		const { hostname, port } = proxyInfo;
		if (remoteSocketWrapper.writer) {
			try { await remoteSocketWrapper.writer.releaseLock(); } catch (e) { }
		}
		const tcp = await connectAndWrite(hostname, port);
		tcp.closed.catch(() => { }).finally(() => safeCloseWebSocket(ws));
		remoteSocketToWS(tcp, ws, null, headerInfo?.responseHeader, log);
	}
	const tcp = await connectAndWrite(headerInfo?.addressRemote, headerInfo?.portRemote);
	remoteSocketToWS(tcp, ws, retry, headerInfo?.responseHeader, log);
}

function safeCloseWebSocket(ws, code = 1000, reason = "Normal Closure") {
	try {
		if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
			ws.close(code, reason);
		}
	} catch (e) {
		console.error("Failed to close WebSocket", e);
	}
}

export class WsDo extends DurableObject {
	constructor(state, env) {
		super(state, env);
		this.state = state;
		this.proxyAddress = env.PYIP ?? "";
		this.uuid4 = env.UUID4 ?? "c3deb827-585e-4137-98a4-2dd4058f9836";
		this.userIDUint8Array = userIdToUint8Array(this.uuid4);
	}

	async fetch(request) {
		if (request.headers.get("Upgrade") !== "websocket") {
			return new Response("Only WebSocket is supported", { status: 400 });
		}
		const userIDUint8Array = this.userIDUint8Array;
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
		const [clientSide, serverSide] = Object.values(new WebSocketPair());
		serverSide.accept();
		let address = "";
		let portLog = "";
		const log = (msg, data) => console.log(`[${address}${portLog}] ${msg}`, data || "");
		const earlyProtoHeader = request.headers.get("sec-websocket-protocol") || "";
		const inbound = makeReadableWebSocketStream(serverSide, earlyProtoHeader, log);
		const remoteSocketWrapper = { value: null, writer: null };
		inbound
			.pipeTo(
				new WritableStream({
					async write(chunk, controller) {
						if (remoteSocketWrapper.writer) {
							try {
								await remoteSocketWrapper.writer.write(chunk);
							} catch (e) {
								controller.error(e);
							}
							return;
						}
						let headerInfo = parseSse1vHeader(chunk, userIDUint8Array);
						if (!headerInfo || headerInfo.hasError) {
							return controller.error(`Header parse error: ${headerInfo?.message}`);
						}
						address = headerInfo?.addressRemote;
						portLog = `-${(Math.random().toString(36) + "000000").slice(2, 8)} tcp`;
						await handleTCPOutBound(remoteSocketWrapper, headerInfo, proxyInfo, serverSide, log);
					},
					close() {
						log("inbound stream closed");
						if (remoteSocketWrapper.writer) {
							try { remoteSocketWrapper.writer.releaseLock(); } catch (e) { }
						}
						if (remoteSocketWrapper.value) {
							try { remoteSocketWrapper.value.close(); } catch (e) { }
						}
					},
					abort(reason) {
						log("inbound stream aborted", reason);
						if (remoteSocketWrapper.writer) {
							try { remoteSocketWrapper.writer.releaseLock(); } catch (e) { }
						}
						if (remoteSocketWrapper.value) {
							try { remoteSocketWrapper.value.close(); } catch (e) { }
						}
					},
				})
			)
			.catch((e) => {
				log("inbound pipe error", e);
			});
		return new Response(null, { status: 101, webSocket: clientSide });
	}
}

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const pathname = url.pathname;
		if (request.headers.get("Upgrade") !== "websocket") {
			if (pathname === "/") {
				const redirectUrl = URLS[Math.floor(Math.random() * URLS.length)];
				return Response.redirect(redirectUrl, 301);
			} else if (pathname === "/cf") {
				return new Response(JSON.stringify(request.cf), { status: 200 });
			}
			return new Response("404 Not Found", { status: 404 });
		}
		const doLocation = env.REGION || "wnam";
		const name = `user-${doLocation}-${env.UUID4 ?? "c3deb827-585e-4137-98a4-2dd4058f9836"}`;
		const id = env.WS_DO.idFromName(name);
		const stub = env.WS_DO.get(id, { locationHint: doLocation });
		return await stub.fetch(request);
	},
};
