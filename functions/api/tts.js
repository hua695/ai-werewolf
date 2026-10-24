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

/* ── 参数白名单 ────────────────────────────────────────────────
   voice / rate / pitch 会被拼进 SSML 的属性里。以前这三个参数
   一个都没校验也没转义，等于开放 XML 注入：
     ?voice=x"><injected>evil</injected><voice name="y
   能注入兄弟元素、改音色、换语言，甚至塞进 <audio src="..."> 让微软
   服务器去取攻击者的地址（盲 SSRF）。

   白名单是最强的防线——只认这九个音色和合法的百分比/赫兹范围，
   注入 payload 根本进不来。转义只是第二道保险。 */
const ALLOWED_VOICES = new Set([
  'zh-CN-XiaoxiaoNeural', 'zh-CN-XiaoyiNeural', 'zh-CN-YunjianNeural',
  'zh-CN-YunxiNeural', 'zh-CN-YunyangNeural', 'zh-CN-XiaochenNeural',
  'zh-CN-XiaomengNeural', 'zh-CN-XiaomoNeural', 'zh-CN-XiaoruiNeural',
  'zh-CN-XiaoshuangNeural', 'zh-CN-XiaoxuanNeural', 'zh-CN-XiaoyanNeural',
  'zh-CN-XiaoyuanNeural', 'zh-CN-XiaozhenNeural',
]);
const RATE_RE = /^[+-]?\d{1,3}%$/;
const PITCH_RE = /^[+-]?\d{1,3}Hz$/;

function buildSsml(text, voice, rate, pitch) {
  /* 三个属性值一律过 xmlEscape，text 同样。双保险。 */
  const v = xmlEscape(voice);
  const r = xmlEscape(rate);
  const p = xmlEscape(pitch);
  const inner = (rate || pitch)
    ? '<prosody rate="' + (r || '0%') + '" pitch="' + (p || '0Hz') + '">' + xmlEscape(text) + '</prosody>'
    : xmlEscape(text);
  return '<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" xml:lang="zh-CN">' +
    '<voice name="' + v + '">' + inner + '</voice></speak>';
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

  /* 参数白名单：不合规直接拒，别把畸形 SSML 发给微软再等它报错 */
  if (!ALLOWED_VOICES.has(voice)) {
    return new Response('invalid voice', { status: 400, headers: CORS });
  }
  if (!RATE_RE.test(rate)) {
    return new Response('invalid rate', { status: 400, headers: CORS });
  }
  if (!PITCH_RE.test(pitch)) {
    return new Response('invalid pitch', { status: 400, headers: CORS });
  }
  /* rate / pitch 的数值范围也要卡，超出微软可接受范围的会被它静默忽略 */
  const rateNum = parseInt(rate, 10);
  const pitchNum = parseInt(pitch, 10);
  if (Math.abs(rateNum) > 100 || Math.abs(pitchNum) > 100) {
    return new Response('rate/pitch out of range', { status: 400, headers: CORS });
  }

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
      /* 不把上游状态码透出去——它暴露微软的风控策略，也给扫描者区分信号 */
      console.warn('tts ws upgrade failed: ' + res.status);
      return new Response('tts unavailable', { status: 502, headers: CORS });
    }
    try {
      ws.accept();
    } catch (e) {
      try { ws.close(); } catch (e2) {}
      return new Response('tts unavailable', { status: 502, headers: CORS });
    }

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
      /* 超时是 504 不是 502——两者对前端的含义不同：
         502 是上游坏了，504 是上游没在时间内响应。 */
      const st = why === 'timeout' ? 504 : 502;
      console.warn('tts no audio: ' + why);
      return new Response('tts unavailable', { status: st, headers: CORS });
    }

    const total = chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }

    return new Response(out, {
      headers: {
        ...CORS,
        'Content-Type': 'audio/mpeg',
        /* private 而不是 public：text 是要合成的用户内容（发言、私聊），
           public 等于授权任何共享缓存（公司代理、公共 WiFi）留存这段音频。
           private 只允许浏览器自己缓存，语义正好是"同一句话别重复合成"。 */
        'Cache-Control': 'private, max-age=86400',
        'X-Content-Type-Options': 'nosniff'
      }
    });
  } catch (e) {
    /* 错误文案不带上游细节（微软的状态码、异常消息）：
       那是给扫描者的 oracle，也能暴露微软的风控策略。详情只进日志。 */
    console.error('tts error', String(e && e.message));
    return new Response('tts unavailable', { status: 502, headers: CORS });
  }
}
