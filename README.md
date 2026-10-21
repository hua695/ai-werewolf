# ai-werewolf

AI 狼人杀 · 多模型混战。一个单文件网页，把 DeepSeek、豆包、Kimi、GLM、Qwen、混元拉到同一张牌桌上互杀。

线上地址：https://chenjinhuawolf.pages.dev/

## 结构

```
index.html              单文件应用（HTML + CSS + JS，无构建、无外部资源）
functions/api/proxy.js  Cloudflare Pages Function，CORS 中转
```

`index.html` 里所有资源都是内联的：头像是用模型给的颜色和汉字现场画的 SVG，音效是 Web Audio 合成的，没有图片和音频文件要加载。

## CORS 中转为什么存在

智谱和混元的接口不放行浏览器跨域直连，所以这两家的 `base` 写成了
`/api/proxy?target=https://open.bigmodel.cn/api/paas/v4`，
由 `functions/api/proxy.js` 在服务端转发。中转只放行 `ALLOW_HOSTS` 里的厂商域名，
不是开放代理。要加新厂商，改 `functions/api/proxy.js` 的白名单。

## 本地跑

直接双击 `index.html` 就能玩。若浏览器限制 `file://` 下的 fetch：

```bash
python -m http.server 8000
# 打开 http://localhost:8000/index.html
```

本地跑时 `/api/proxy` 不存在，智谱和混元会连不上，其余厂商不受影响；
需要连这两家就用 `wrangler pages dev .`（会自动挂上 functions）。

## 玩法要点

- 右侧「模型池」添几家模型，填模型名与密钥，开局按座位随机分配，同一家可以出多个玩家。
- 勾「让 AI 自己起名、写人设、画头像」，每张椅子会请一个模型上来自己设定身份。
- 座位卡上姓名下面直接写着该玩家跑在哪个模型上，点开头像能看完整档案：人设、口吻、内心独白、投票命中率。
- 等待时能押注：押 10 猜本轮谁被放逐（中回 25），押 20 猜最终阵营（中回 40）。
- 右上角「快进」或按 `F` 跳掉停顿；`空格` 暂停。
- 平票进 PK，PK 再平票无人出局。6 人局屠城，9/12 人局屠边。

## 部署

推到 GitHub `main` 分支，Cloudflare Pages 自动构建上线。没有构建步骤，静态目录就是仓库根目录。
