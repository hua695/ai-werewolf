/* 临时诊断：确认边缘函数发出的请求头是否被保留，以及能否连到微软的域名。
   用完即删。 */
export async function onRequest() {
  const out = {};
  try {
    const r = await fetch('https://httpbingo.org/headers', {
      headers: {
        Origin: 'chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        Pragma: 'no-cache'
      }
    });
    out.echoStatus = r.status;
    out.echoBody = (await r.text()).slice(0, 900);
  } catch (e) {
    out.echoError = String(e && e.message);
  }
  try {
    const r2 = await fetch('https://speech.platform.bing.com/consumer/speech/synthesize/readaloud/edge/v1?TrustedClientToken=6A5AA1D4EAFF4E9FB37E23D68491D6F4', {
      headers: { Upgrade: 'websocket', Origin: 'chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold' }
    });
    out.msStatus = r2.status;
    out.msHasSocket = !!r2.webSocket;
  } catch (e) {
    out.msError = String(e && e.message);
  }
  return new Response(JSON.stringify(out, null, 2), {
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}
