
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
    // 路径格式: /api/proxy?target=https://api.example.com/v1/chat/completions
    const target = url.searchParams.get('target');
    if (!target) {
      return new Response('Missing target parameter', { status: 400, headers: corsHeaders });
    }

    let newRequest = new Request(target, request);
    newRequest.headers.set("Origin", new URL(target).origin);

    let response = await fetch(newRequest);
    response = new Response(response.body, response);
    Object.entries(corsHeaders).forEach(([k, v]) => response.headers.set(k, v));
    return response;
  } catch (e) {
    return new Response("Proxy error: " + e.message, { status: 500, headers: corsHeaders });
  }
}
