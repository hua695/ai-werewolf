/* ═══════════════════════════════════════════════════════════════
   AI 狼人杀 · 上游 API 转发代理
   ---------------------------------------------------------------
   GET/POST /api/proxy?target=<上游URL>
   把请求转发到上游 LLM / TTS 接口，并把响应原样带回。

   为什么需要这一层：浏览器的 CORS 限制挡住大部分第三方 API，
   而各家厂商又不允许在服务端代转（智谱、混元这类只能靠边缘中转）。

   ⚠️ 这个接口是公开的，任何人都能调。所以它同时是一把双刃剑：
      放松了就变成开放代理（可打内网、可白嫖、可烧配额），
      收紧了就有人用不了。下面每一处限制都是为此。
   ═══════════════════════════════════════════════════════════════ */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,HEAD,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

/* ── 内网 / 保留地址黑名单 ─────────────────────────────────────
   光靠黑名单挡不住 DNS 重绑定（攻击者控制的域名第一次解析到公网、
   第二次解析到 127.0.0.1），所以真正的防线是下面的"只放行固定域名"。
   这份黑名单是第二道保险：万一将来放宽了域名规则，这里还能拦一道。 */
function isPrivateHost(hostRaw) {
  /* 去掉 FQDN 尾点：metadata.google.internal. 与 metadata.google.internal
     解析到同一台机器，但 endsWith('.internal') 对前者返回 false。 */
  const host = String(hostRaw || '').toLowerCase().replace(/\.$/, '');

  /* IPv6 字面量：[::1] / [::ffff:7f00:1] / [fe80::1] / [fc00::1]
     URL 解析器会把 [::ffff:127.0.0.1] 规范化成 [::ffff:7f00:1]，
     所以只匹配 "::1" 是漏的——整个 IPv4-mapped 段和私网段都要覆盖。 */
  if (host.startsWith('[') && host.endsWith(']')) {
    const v6 = host.slice(1, -1);
    if (v6 === '::' || v6 === '::1') return true;              // 未指定 / 回环
    if (v6.startsWith('::ffff:')) return true;                // IPv4 映射，一律拒
    if (/^fe[89ab]/.test(v6)) return true;                     // fe80::/10 链路本地
    if (/^f[cd]/.test(v6)) return true;                        // fc00::/7 唯一本地
    return false;
  }

  /* IPv4：new URL() 已经把十进制/八进制/十六进制写法规范化成点分十进制，
     所以这里只需要处理点分形式。 */
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0) return true;                                 // 0.0.0.0/8
    if (a === 10) return true;                                // 10/8
    if (a === 127) return true;                               // 127/8 回环
    if (a === 169 && b === 254) return true;                   // 169.254/16 链路本地（含元数据）
    if (a === 172 && b >= 16 && b <= 31) return true;          // 172.16/12
    if (a === 192 && b === 168) return true;                   // 192.168/16
    if (a === 100 && b >= 64 && b <= 127) return true;         // 100.64/10 CGNAT
    if (a === 198 && (b === 18 || b === 19)) return true;      // 198.18/15 基准测试
    if (a >= 224) return true;                                // 组播 / 保留
    return false;
  }

  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host.endsWith('.internal') || host.endsWith('.local')) return true;
  if (host === 'metadata.google.internal') return true;
  if (host === '100.100.100.200') return true;                 // 阿里云元数据
  return false;
}

/* ── 固定放行的域名 ────────────────────────────────────────────
   前端实际会用到的就这几个：
     智谱 GLM      open.bigmodel.cn
     腾讯混元      tokenhub.tencentmaas.com
     百度 TTS      fanyi.baidu.com
   「自定义」provider 允许用户填任意 OpenAI 兼容地址，所以不能只认白名单。
   折中办法：非白名单的域名一律要求走 HTTPS，并且仍然要过内网黑名单。
   —— 已知缺口是 DNS 重绑定（Worker 拿不到解析后的 IP，无法做 IP 钉扎），
   所以白名单里的三家是严格放行，自定义地址是"尽最大努力"放行。 */
const PINNED = new Set([
  'open.bigmodel.cn',
  'tokenhub.tencentmaas.com',
  'fanyi.baidu.com',
]);

/* 请求体上限：LLM 的 prompt 加输出，1MB 绰绰有余。
   不限制的话，攻击者可以每次往上游灌 100MB（平台上限），带宽和上游配额买单。 */
const MAX_BODY = 1024 * 1024;

/* 上游响应超时。LLM 推理动辄几十秒，给 120 秒；
   TTS 合成通常 3~10 秒，但共用这个接口，取同一个值不额外分叉。 */
const UPSTREAM_TIMEOUT_MS = 120000;

/* 逐跳复检地取上游：禁掉自动跳转，每一跳都重新过白名单与黑名单。
   原来的实现只用 new Request(url, {...}) 重建请求，redirect 取默认值 follow，
   于是上游一个 302 就能把整个 SSRF 防线绕过去——检查只做了一次，
   跳转后的目标从不复检。 */
async function safeFetch(targetUrl, headers, method, body, maxHops = 3) {
  let url = targetUrl;
  for (let hop = 0; hop <= maxHops; hop++) {
    const pinned = PINNED.has(url.hostname.toLowerCase());
    if (!pinned) {
      if (isPrivateHost(url.hostname)) {
        return { error: 'Forbidden target', status: 403 };
      }
      /* 非白名单的域名强制 HTTPS，避免明文流量和 http 跳转绕过 */
      if (url.protocol !== 'https:') {
        return { error: 'Bad protocol', status: 400 };
      }
    }
    const req = new Request(url.toString(), {
      method: hop === 0 ? method : 'GET',
      headers,
      body: hop === 0 ? body : null,
      redirect: 'manual',
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
    let res;
    try {
      res = await fetch(req);
    } catch (e) {
      if (e && e.name === 'TimeoutError') {
        return { error: 'Upstream timeout', status: 504 };
      }
      return { error: 'Upstream unreachable', status: 502 };
    }
    /* 手动模式下 3xx 会带着 location 头返回，这里自己判断要不要跟 */
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      let next;
      try {
        next = new URL(res.headers.get('location'), url);
      } catch (e) {
        return { error: 'Bad redirect', status: 502 };
      }
      /* 跳转目标也要过白名单/黑名单——不能只查第一跳 */
      if (!PINNED.has(next.hostname.toLowerCase()) && isPrivateHost(next.hostname)) {
        return { error: 'Forbidden redirect', status: 403 };
      }
      url = next;
      continue;
    }
    return { res };
  }
  return { error: 'Too many redirects', status: 502 };
}

export async function onRequest(context) {
  const { request } = context;

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: CORS });
  }
  if (request.method !== 'GET' && request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: CORS });
  }

  let targetUrl = null;
  try {
    const url = new URL(request.url);
    const target = url.searchParams.get('target');
    if (!target) {
      return new Response('Missing target parameter', { status: 400, headers: CORS });
    }
    targetUrl = new URL(target);
    if (!/^https?:$/.test(targetUrl.protocol)) {
      return new Response('Bad protocol', { status: 400, headers: CORS });
    }
    if (isPrivateHost(targetUrl.hostname)) {
      /* 本机地址（Ollama 之类）本来就应该浏览器直连，不该走这个公网代理——
         放行它等于把整个内网暴露出去。提示写清楚，别让人以为是故障。 */
      return new Response('Forbidden target: local address must be called directly, not via proxy', {
        status: 403, headers: CORS
      });
    }
  } catch (e) {
    return new Response('Bad target', { status: 400, headers: CORS });
  }

  /* 请求体大小：Content-Length 头缺失时（chunked）无法预判，
     交给平台层兜底，这里能查到的先查。 */
  const cl = Number(request.headers.get('content-length') || 0);
  if (cl > MAX_BODY) {
    return new Response('Payload too large', { status: 413, headers: CORS });
  }

  /* ── 转发头：白名单式，不要把客户端的头全带过去 ──────────────
     原来的 new Headers(request.headers) 会把客户端的 Cookie、
     Authorization、CF-Connecting-IP 全交给上游——攻击者只要让
     受害者浏览器打一次这个接口，他站点的 Cookie 就到了攻击者手里。 */
  const headers = new Headers();
  const passthrough = ['content-type', 'accept', 'accept-language'];
  for (const k of passthrough) {
    const v = request.headers.get(k);
    if (v) headers.set(k, v);
  }
  /* Authorization 是这个接口存在的意义（转交 LLM 的 API Key），
     但只对白名单域名转交，自定义地址那部分不该拿到别人的凭据。 */
  if (PINNED.has(targetUrl.hostname.toLowerCase())) {
    const auth = request.headers.get('authorization');
    if (auth) headers.set('authorization', auth);
  }
  /* 别伪装成浏览器：伪装会废掉上游针对 UA 的风控，也掩盖了
     "这是边缘出站"这个事实。上游需要特定 Origin 的情况由具体厂商决定。 */
  headers.set('User-Agent', 'ai-werewolf-proxy/1.0');
  headers.set('Origin', targetUrl.origin);
  headers.set('Referer', targetUrl.origin + '/');

  /* GET/HEAD 不能带 body：Fetch 规范下 Request 构造函数会抛 TypeError。
     Workers 里 GET 请求的 body 可能是零长度流而非 null（只要客户端带了
     Content-Length: 0），不判一下整个请求会变成 500。 */
  const hasBody = request.method === 'POST' && request.body ? request.body : null;

  const out = await safeFetch(targetUrl, headers, request.method, hasBody);
  if (out.error) {
    /* 错误文案不要带上游的细节（主机名、解析错误、状态码）：
     那是给攻击者的扫描 oracle，能区分"域名不存在/连不上/TLS 失败/超时"。 */
    return new Response(out.error, { status: out.status, headers: CORS });
  }
  const response = out.res;

  /* ── 回写响应头 ─────────────────────────────────────────────
     整体复制上游的头会有三个坑：
       · Set-Cookie 存活 → 上游能在你的域名下种 Cookie（会话固定）
       · Content-Encoding / Content-Length 存活 → Workers 已经解压过，
         头和 body 对不上，浏览器会报 ERR_CONTENT_DECODING_FAILED
       · 上游自己的 CORS 头 → 我们要自己统一设，别让上游说了算 */
  const responseHeaders = new Headers(response.headers);
  responseHeaders.delete('set-cookie');
  responseHeaders.delete('content-encoding');
  responseHeaders.delete('content-length');
  responseHeaders.delete('access-control-allow-origin');
  responseHeaders.delete('access-control-allow-credentials');
  responseHeaders.delete('access-control-allow-headers');
  responseHeaders.delete('access-control-allow-methods');
  responseHeaders.delete('location');
  Object.entries(CORS).forEach(([k, v]) => responseHeaders.set(k, v));
  responseHeaders.set('X-Content-Type-Options', 'nosniff');

  /* body 走流式透传，不整块读进内存——上游返回多大都不占 Worker 内存。 */
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}
