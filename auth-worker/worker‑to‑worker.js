import { WorkerEntrypoint } from "cloudflare:workers";

function parseIPv4(ip) {
	return ip.split('.').map(x => parseInt(x, 10));
}

function parseIPv6(ip) {
	const parts = ip.split("::");
	let head = parts[0].split(":").filter(Boolean);
	let tail = parts[1] ? parts[1].split(":").filter(Boolean) : [];
	let missing = 8 - (head.length + tail.length);
	let full = [...head, ...Array(missing).fill("0"), ...tail];
	return full.map(x => parseInt(x || "0", 16));
}

function ipToBigInt(ip) {
	if (ip.includes(".")) { // IPv4
		const [a, b, c, d] = parseIPv4(ip);
		return BigInt((a << 24) | (b << 16) | (c << 8) | d);
	} else { // IPv6
		const parts = parseIPv6(ip);
		return parts.reduce((acc, part) => (acc << 16n) + BigInt(part), 0n);
	}
}

function inCIDR(ip, cidr) {
	const [range, bits = "32"] = cidr.split('/');
	const ipBig = ipToBigInt(ip);
	const rangeBig = ipToBigInt(range);
	const prefix = parseInt(bits, 10);

	if (ip.includes(".") && range.includes(".")) {
		// IPv4
		const mask = ~((1 << (32 - prefix)) - 1) >>> 0;
		return Number(ipBig & BigInt(mask)) === Number(rangeBig & BigInt(mask));
	} else if (!ip.includes(".") && !range.includes(".")) {
		// IPv6
		const mask = (1n << 128n) - (1n << (128n - BigInt(prefix)));
		return (ipBig & mask) === (rangeBig & mask);
	} else {
		return false; // IPv4 vs IPv6 不匹配
	}
}

function isIpMatch(ip, rule) {
	// 允许所有 IPv4 / IPv6 流量
	if (["0.0.0.0/0", "::/0"].includes(rule)) return true;
	// 判断 rule 是 CIDR 还是单个 IP
	if (rule.includes("/")) {
		return inCIDR(ip, rule);
	} else {
		return ip === rule; // 精确匹配
	}
}

export default class AuthWorker extends WorkerEntrypoint {
	async fetch() {
		return new Response("Not Found", { status: 404 });
	}

	// RPC：主 Worker 直接调用 await env.AUTH_SERVICE.check(ip)
	async check(ip) {
		if (!ip) return false;
		const raw = (this.env.ALLOWED_RULES || "").trim();
		if (!raw) return false;
		// 支持逗号/换行/空白分隔
		const rules = raw.split(/[, \n\r\t]+/).map(s => s.trim()).filter(Boolean);
		return rules.some(rule => isIpMatch(ip, rule));
	}

	// 可选：查看当前规则（检测是否绑定成功，可以调用该 worker）
	async rules() {
		return (this.env.ALLOWED_RULES || "").trim();
	}
}

/** 主 Worker 调用示例
 * const allowed = await this.env.AUTH_SERVICE.check(ip);
 * if (!allowed) {
 *   return new Response("Forbidden", { status: 403 });
 * }
 */

/** 主 wrangler.toml
 * [[services]]
 * binding = "AUTH_SERVICE"
 * service = "auth-worker" // => auth-worker.<username>.workers.dev
 */
