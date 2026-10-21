// Cloudflare Pages Function · CORS 中转
// 用途：智谱、混元这类不让浏览器直连的接口，走这里转发。
// 调用：/api/proxy?target=https://open.bigmodel.cn/api/paas/v4/chat/completions
//
// 只放行下面这些厂商域名，避免变成谁都能蹭的公共代理。

const ALLOW_HOSTS = [
  'api.deepseek.com',
  'ark.cn-beijing.volces.com',
  'api.moonshot.cn',
  'open.bigmodel.cn',
  'dashscope.aliyuncs.com',
  'tokenhub.tencentmaas.com',
  'api.hunyuan.cloud.tencent.com'
];

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400'
};

function hostAllowed(host) {
  const h = String(host || '').toLowerCase();
  return ALLOW_HOSTS.some(a => h === a || h.endsWith('.' + a));
}

const deny = (msg, status) => new Response(msg, { status, headers: CORS });

export async function onRequest(context) {
  const { request } = context;

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (request.method !== 'POST') return deny('Method Not Allowed', 405);

  let target;
  try {
    const raw = new URL(request.url).searchParams.get('target');
    if (!raw) return deny('Missing target parameter', 400);
    target = new URL(raw);
  } catch (e) {
    return deny('Bad target parameter', 400);
  }

  if (target.protocol !== 'https:') return deny('Only https targets allowed', 400);
  if (!hostAllowed(target.hostname)) return deny('Target host not allowed: ' + target.hostname, 403);

  const headers = new Headers();
  const ct = request.headers.get('content-type');
  if (ct) headers.set('Content-Type', ct);
  const auth = request.headers.get('authorization');
  if (auth) headers.set('Authorization', auth);
  headers.set('Accept', 'application/json');

  try {
    const upstream = await fetch(target.toString(), {
      method: 'POST',
      headers,
      body: await request.text(),
      redirect: 'follow'
    });

    const out = new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: upstream.headers
    });
    // 压缩交给平台处理，不然编码头会和实际内容对不上
    out.headers.delete('content-encoding');
    out.headers.delete('content-length');
    out.headers.delete('set-cookie');
    Object.entries(CORS).forEach(([k, v]) => out.headers.set(k, v));
    return out;
  } catch (e) {
    return deny('Proxy error: ' + (e && e.message ? e.message : String(e)), 502);
  }
}
