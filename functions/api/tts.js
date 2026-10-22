/* 微软 Edge TTS 边缘代理
   GET /api/tts?text=...&voice=zh-CN-YunyangNeural&rate=-5%&pitch=-2Hz
   返回 audio/mpeg。任何一步失败都返回 4xx/5xx，前端会回落浏览器合成。

   为什么需要这一层：微软的朗读接口是 WebSocket，且校验 Origin/UA，
   网页里直接连会被拒（实测 opened=error）。边缘函数可以带自定义头，
   也能做 WebSocket 出站，所以放在这里。 */

const TRUSTED = '6A5AA1D4EAFF4E9FB37E23D68491D6F4';
/* Workers 的 fetch 不接受 wss:// 协议，WebSocket 出站要用 https + Upgrade 头 */
const WSS = 'https://speech.platform.bing.com/consumer/speech/synthesize/readaloud/edge/v1';
const CHROMIUM_VERSION = '130.0.2849.68';
const MAX_CHARS = 800;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,OPTIONS',
  'Access-Control-Max-Age': '86400'
};

/* Sec-MS-GEC：时间窗（5 分钟对齐）+ 固定 token 的 SHA-256，微软用来校验客户端 */
async function secMsGec() {
  let ticks = Math.floor((Date.now() / 1000 + 11644473600) * 1e7);
  ticks -= ticks % 3e9;
  const data = new TextEncoder().encode(String(ticks) + TRUSTED);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function uuid() {
  return (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2)).replace(/-/g, '');
}

function xmlEscape(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function buildSsml(text, voice, rate, pitch) {
  const inner = (rate || pitch)
    ? '<prosody rate="' + (rate || '0%') + '" pitch="' + (pitch || '0Hz') + '">' + xmlEscape(text) + '</prosody>'
    : xmlEscape(text);
  return '<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" xml:lang="zh-CN">' +
    '<voice name="' + voice + '">' + inner + '</voice></speak>';
}

export async function onRequestOptions() {
  return new Response(null, { headers: CORS });
}

export async function onRequestGet(context) {
  const { request } = context;
  const u = new URL(request.url);
  const text = (u.searchParams.get('text') || '').trim().slice(0, MAX_CHARS);
  if (!text) return new Response('missing text', { status: 400, headers: CORS });

  const voice = u.searchParams.get('voice') || 'zh-CN-XiaoxiaoNeural';
  const rate = u.searchParams.get('rate') || '0%';
  const pitch = u.searchParams.get('pitch') || '0Hz';

  try {
    const gec = await secMsGec();
    const cid = uuid();
    const url = WSS + '?TrustedClientToken=' + TRUSTED +
      '&Sec-MS-GEC=' + gec +
      '&Sec-MS-GEC-Version=1-' + CHROMIUM_VERSION +
      '&ConnectionId=' + cid;

    const res = await fetch(url, {
      headers: {
        Upgrade: 'websocket',
        // 微软只认 Edge 朗读扩展发起的连接，Origin 必须是这个扩展 ID
        Origin: 'chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
          'Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'Accept-Language': 'en-US,en;q=0.9',
        Pragma: 'no-cache',
        'Cache-Control': 'no-cache'
      }
    });

    const ws = res.webSocket;
    if (!ws) {
      return new Response('ws upgrade failed: ' + res.status, { status: 502, headers: CORS });
    }
    ws.accept();

    const chunks = [];
    const finished = new Promise(resolve => {
      const timer = setTimeout(() => resolve('timeout'), 20000);
      ws.addEventListener('message', ev => {
        if (typeof ev.data === 'string') {
          if (ev.data.indexOf('Path:turn.end') >= 0) { clearTimeout(timer); resolve('end'); }
          return;
        }
        const buf = new Uint8Array(ev.data);
        if (buf.length < 2) return;
        const hlen = (buf[0] << 8) | buf[1];
        let header = '';
        try { header = new TextDecoder().decode(buf.subarray(2, 2 + hlen)); } catch (e) { return; }
        if (/Path:audio/i.test(header)) chunks.push(buf.subarray(2 + hlen));
      });
      ws.addEventListener('close', () => { clearTimeout(timer); resolve('close'); });
      ws.addEventListener('error', () => { clearTimeout(timer); resolve('error'); });
    });

    ws.send('X-Timestamp:' + new Date().toISOString() + '\r\n' +
      'Content-Type:application/json; charset=utf-8\r\nPath:speech.config\r\n\r\n' +
      JSON.stringify({
        context: {
          synthesis: {
            audio: {
              metadataoptions: { sentenceBoundaryEnabled: 'false', wordBoundaryEnabled: 'false' },
              outputFormat: 'audio-24khz-48kbitrate-mono-mp3'
            }
          }
        }
      }));

    ws.send('X-RequestId:' + cid + '\r\n' +
      'Content-Type:application/ssml+xml\r\n' +
      'X-Timestamp:' + new Date().toISOString() + 'Z\r\nPath:ssml\r\n\r\n' +
      buildSsml(text, voice, rate, pitch));

    const why = await finished;
    try { ws.close(); } catch (e) { /* 忽略 */ }

    if (!chunks.length) {
      return new Response('no audio (' + why + ')', { status: 502, headers: CORS });
    }

    const total = chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }

    return new Response(out, {
      headers: {
        ...CORS,
        'Content-Type': 'audio/mpeg',
        // 同一句话反复播放走浏览器缓存，省一次往返
        'Cache-Control': 'public, max-age=86400'
      }
    });
  } catch (e) {
    return new Response('tts error: ' + (e && e.message), { status: 502, headers: CORS });
  }
}
