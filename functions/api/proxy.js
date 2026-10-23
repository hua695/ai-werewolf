export async function onRequest(context) {
  const { request } = context;
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const url = new URL(request.url);
    const target = url.searchParams.get('target');
    if (!target) {
      return new Response('Missing target parameter', { status: 400, headers: corsHeaders });
    }

    // ── 防 SSRF：这个接口是公开的，不能让任何人拿它去打内网或云元数据 ──
    const targetUrl = new URL(target);
    if (!/^https?:$/.test(targetUrl.protocol)) {
      return new Response('Bad protocol', { status: 400, headers: corsHeaders });
    }
    const host = targetUrl.hostname.toLowerCase();
    const isPrivate = /^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|\[?::1\]?)/.test(host) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
      host.endsWith('.internal') || host.endsWith('.local') ||
      host === 'metadata.google.internal' || host === '100.100.100.200';
    if (isPrivate) {
      return new Response('Forbidden target', { status: 403, headers: corsHeaders });
    }

    // 构建请求，加必要的header
    const headers = new Headers(request.headers);
    headers.set("Origin", targetUrl.origin);
    headers.set("Referer", targetUrl.origin + "/");
    headers.set("User-Agent", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36");

    const newRequest = new Request(target, {
      method: request.method,
      headers: headers,
      body: request.body,
    });

    let response = await fetch(newRequest);
    
    // 创建新的响应，保留原始内容类型，加上CORS头
    const responseHeaders = new Headers(response.headers);
    Object.entries(corsHeaders).forEach(([k, v]) => responseHeaders.set(k, v));
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
  } catch (e) {
    return new Response("Proxy error: " + e.message, { status: 500, headers: corsHeaders });
  }
}
