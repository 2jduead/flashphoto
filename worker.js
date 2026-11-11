/**
 * 阅后即焚（闪照） - Cloudflare Worker
 * 纯单文件：原生 JS + R2 + KV + TailwindCSS + AES加密 + 不限次数群发 + HEIC/HEIF 全面兼容
 * v2：新增「单张专属管理密码」—— 立即焚毁 / 调整有效期 / 调整查看人数（原链接不变）
 */

// --- 0. 常量 ---
const MAX_LIFETIME_MS = 7 * 24 * 3600 * 1000;   // 闪照最长存活期：上传后 7 天（与隐私承诺一致）
const KV_GRACE_MS = 24 * 3600 * 1000;          // KV 记录比最长存活期多留 1 天，避免边界误判
// 4 位数字仅 1 万种组合，必须严格限制尝试次数：
const MANAGE_MAX_FAILS = 5;                    // 单张闪照 15 分钟内允许输错 5 次，超出临时锁定
const MANAGE_LOCK_TTL = 900;                   // 临时锁定时长（秒）
const MANAGE_TOTAL_FAILS = 20;                 // 累计输错 20 次 → 该照片管理功能永久锁定（照片仍按原设置到期）
const PWD_DIGITS = 4;                          // 4 位纯数字管理密码，服务器随机生成
const MANAGE_PEPPER = '_flash_manage_pepper_2026';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// --- 1. 后端 API 与路由逻辑 ---
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // 路由：主页上传页
        if (request.method === 'GET' && path === '/') {
            return html(htmlIndex);
        }

        // 路由：管理页（/m 或 /m/<id>）—— 页面本身不含任何闪照数据，ID 由前端从地址栏读取
        if (request.method === 'GET' && (path === '/m' || path.startsWith('/m/'))) {
            return html(htmlManage, { 'Referrer-Policy': 'no-referrer', 'X-Robots-Tag': 'noindex' });
        }

        // 路由：处理上传
        if (request.method === 'POST' && path === '/api/upload') {
            const formData = await request.formData();
            const file = formData.get('file');
            const maxTimeRaw = String(formData.get('maxTime') || '5');
            const maxViewsRaw = parseInt(formData.get('maxViews') ?? '1', 10);
            const wechatOnly = formData.get('wechatOnly') === 'true' ? 'true' : 'false';

            if (!file || typeof file === 'string') return new Response('No file provided', { status: 400 });

            // 限制 20MB
            if (file.size > 20 * 1024 * 1024) {
                return new Response('文件过大，超出 20MB 限制', { status: 413 });
            }

            const maxTime = ['3', '5', '10'].includes(maxTimeRaw) ? maxTimeRaw : '5';
            const maxViews = Number.isInteger(maxViewsRaw) && maxViewsRaw >= 0 && maxViewsRaw <= 100000 ? maxViewsRaw : 1;

            const id = crypto.randomUUID();
            const createdAt = Date.now();
            const maxExpiresAt = createdAt + MAX_LIFETIME_MS;

            // 有效期：支持 expiresAt（自定义毫秒时间戳）或 expiresIn（相对秒数），默认 7 天
            let expiresAt = maxExpiresAt;
            const expiresAtParam = formData.get('expiresAt');
            const expiresInParam = formData.get('expiresIn');
            if (expiresAtParam !== null && expiresAtParam !== '') {
                const ex = Math.floor(Number(expiresAtParam));
                if (!Number.isFinite(ex)) {
                    return json({ error: '有效期时间格式错误' }, 400);
                }
                if (ex < createdAt + 60 * 1000) {
                    return json({ error: '有效期至少要在 1 分钟之后' }, 400);
                }
                if (ex > maxExpiresAt + 60 * 1000) {
                    return json({ error: '有效期不能晚于上传后 7 天' }, 400);
                }
                expiresAt = Math.min(ex, maxExpiresAt);
            } else if (expiresInParam !== null && expiresInParam !== '') {
                const sec = Math.floor(Number(expiresInParam));
                if (!Number.isFinite(sec) || sec < 60 || sec * 1000 > MAX_LIFETIME_MS) {
                    return json({ error: '有效期范围应为 1 分钟至 7 天' }, 400);
                }
                expiresAt = createdAt + sec * 1000;
            }

            // 🔒 AES-GCM 加密二进制流
            const rawBuffer = await file.arrayBuffer();
            const key = await getCipherKey(id);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encryptedBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, rawBuffer);

            // 存入 R2：加密后的乱码 + 不可变的元数据
            await env.BUCKET.put(id, encryptedBuffer, {
                customMetadata: {
                    maxTime,
                    maxViews: String(maxViews),            // 初始值，仅作 KV 未同步时的兜底
                    expiresAt: String(expiresAt),          // 初始值，仅作 KV 未同步时的兜底
                    wechatOnly,
                    contentType: file.type || 'application/octet-stream',
                    iv: Array.from(iv).join(','),
                    createdAt: String(createdAt),
                    managed: '1'
                }
            });

            // 🔑 生成专属管理密码：只返回明文一次，服务器仅保存「盐 + 哈希」
            const password = generatePassword();
            const salt = randomHex(16);
            const hash = await hashPassword(password, salt);

            const ttl = kvTtl(createdAt);
            await Promise.all([
                env.VIEW_RECORDS.put(`views:${id}`, '0', { expirationTtl: ttl }),
                env.VIEW_RECORDS.put(`meta:${id}`, JSON.stringify({ maxViews, expiresAt, createdAt, salt, hash }), { expirationTtl: ttl })
            ]);

            return json({
                url: `${url.origin}/v/${id}`,
                manageUrl: `${url.origin}/m/${id}`,
                password: formatPassword(password),
                expiresAt
            });
        }

        // 路由：访客查看页（链接永远不变）
        if (request.method === 'GET' && path.startsWith('/v/')) {
            const id = path.split('/')[2];
            if (!isValidId(id)) return errorPage('⚠️ 闪照已不可查看或不存在');

            const obj = await env.BUCKET.head(id);
            if (!obj) return errorPage('⚠️ 闪照已不可查看或不存在');

            const state = await loadState(env, id, obj);
            if (state.expired) {
                ctx.waitUntil(purgePhoto(env, id));
                return errorPage('⚠️ 闪照已过期，不可查看');
            }

            if (obj.customMetadata.wechatOnly === 'true') {
                const ua = request.headers.get('User-Agent') || '';
                if (!ua.toLowerCase().includes('micromessenger')) {
                    return errorPage('⚠️ 此闪照仅限微信内查看<br><span class="text-sm text-gray-400 mt-3 block font-normal">请将链接复制并发送到微信对话框中打开</span>');
                }
            }

            const currentViews = parseInt(await env.VIEW_RECORDS.get(`views:${id}`) || '0');
            if (state.maxViews !== 0 && currentViews >= state.maxViews) return errorPage('⚠️ 闪照已达最大查看次数，不可查看');

            const userHash = await getUserHash(request);
            const hasViewed = await env.VIEW_RECORDS.get(`user:${id}:${userHash}`);
            if (hasViewed) return errorPage('⚠️ 您已查看过此闪照，不可再次查看');

            return html(htmlViewer.replace('{{ID}}', id));
        }

        // 路由：安全代理获取并解密数据流
        if (request.method === 'GET' && path.startsWith('/api/img/')) {
            const id = path.split('/')[3];
            if (!isValidId(id)) return new Response('Not found', { status: 404 });

            const obj = await env.BUCKET.get(id);
            if (!obj) return new Response('Not found', { status: 404 });

            const state = await loadState(env, id, obj);
            if (state.expired) {
                ctx.waitUntil(purgePhoto(env, id));
                return new Response('Expired', { status: 403 });
            }

            const currentViews = parseInt(await env.VIEW_RECORDS.get(`views:${id}`) || '0');
            if (state.maxViews !== 0 && currentViews >= state.maxViews) return new Response('Burned', { status: 403 });

            // 🔓 解密逻辑
            const encryptedBuffer = await obj.arrayBuffer();
            const key = await getCipherKey(id);
            const iv = new Uint8Array(obj.customMetadata.iv.split(',').map(Number));

            let decryptedBuffer;
            try {
                decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encryptedBuffer);
            } catch (err) {
                return new Response('Decryption failed', { status: 500 });
            }

            const headers = new Headers();
            headers.set('x-max-time', obj.customMetadata.maxTime || '5');
            headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            headers.set('Content-Type', obj.customMetadata.contentType);

            return new Response(decryptedBuffer, { headers });
        }

        // 路由：长按触发销毁机制
        if (request.method === 'POST' && path.startsWith('/api/mark/')) {
            const id = path.split('/')[3];
            if (!isValidId(id)) return new Response('Gone', { status: 410 });

            const obj = await env.BUCKET.head(id);
            if (!obj) return new Response('Gone', { status: 410 });

            const state = await loadState(env, id, obj);
            if (state.expired) {
                await purgePhoto(env, id);
                return new Response('Gone', { status: 410 });
            }

            const userHash = await getUserHash(request);
            const currentViews = parseInt(await env.VIEW_RECORDS.get(`views:${id}`) || '0');
            const newViews = currentViews + 1;

            if (state.maxViews !== 0 && newViews >= state.maxViews) {
                await purgePhoto(env, id);
            } else {
                const ttl = kvTtl(state.createdAt);
                await env.VIEW_RECORDS.put(`views:${id}`, newViews.toString(), { expirationTtl: ttl });
                await env.VIEW_RECORDS.put(`user:${id}:${userHash}`, '1', { expirationTtl: ttl });
            }

            return new Response('OK');
        }

        // 路由：单张闪照管理 API（凭专属密码）
        if (request.method === 'POST' && path.startsWith('/api/manage/')) {
            const id = path.split('/')[3];
            return handleManage(request, env, ctx, id);
        }

        return new Response('Not Found', { status: 404 });
    },

    // 可选：在 Dashboard 为 Worker 配置 Cron Trigger（如每小时）后，自动清理已过期的闪照
    async scheduled(event, env, ctx) {
        ctx.waitUntil(cleanupExpired(env));
    }
};

// --- 2. 管理功能 ---

async function handleManage(request, env, ctx, id) {
    if (!isValidId(id)) return json({ error: '链接无效' }, 400);

    let body;
    try { body = await request.json(); } catch (e) { return json({ error: '请求格式错误' }, 400); }

    const action = body.action || 'info';
    const password = normalizePassword(body.password);
    if (!password) return json({ error: '请输入管理密码' }, 400);

    const obj = await env.BUCKET.head(id);
    if (!obj) return json({ error: '闪照已焚毁或不存在', gone: true }, 404);

    const meta = safeParse(await env.VIEW_RECORDS.get(`meta:${id}`));
    if (!meta || !meta.hash) {
        if (obj.customMetadata && obj.customMetadata.managed === '1') {
            return json({ error: '管理数据正在全球节点同步，请约 1 分钟后重试' }, 503);
        }
        return json({ error: '该闪照创建于管理功能上线之前，不支持管理' }, 400);
    }

    // 🛡️ 防爆破（4 位数字密码）：15 分钟内最多错 5 次；累计错 20 次永久锁定管理（猜中概率 ≤ 0.2%）
    const failKey = `fail:${id}`;
    const totalKey = `failtotal:${id}`;
    const [fails, totalFails] = await Promise.all([
        env.VIEW_RECORDS.get(failKey).then(v => parseInt(v || '0')),
        env.VIEW_RECORDS.get(totalKey).then(v => parseInt(v || '0'))
    ]);
    if (totalFails >= MANAGE_TOTAL_FAILS) {
        return json({ error: '该闪照因密码输错次数过多，管理功能已永久锁定；照片仍会按原设置到期焚毁', locked: true }, 423);
    }
    if (fails >= MANAGE_MAX_FAILS) return json({ error: '密码错误次数过多，请 15 分钟后再试' }, 429);

    const hash = await hashPassword(password, meta.salt);
    if (!timingSafeEqual(hash, meta.hash)) {
        await Promise.all([
            env.VIEW_RECORDS.put(failKey, String(fails + 1), { expirationTtl: MANAGE_LOCK_TTL }),
            env.VIEW_RECORDS.put(totalKey, String(totalFails + 1), { expirationTtl: kvTtl(meta.createdAt) })
        ]);
        const totalLeft = MANAGE_TOTAL_FAILS - totalFails - 1;
        const left = Math.min(MANAGE_MAX_FAILS - fails - 1, totalLeft);
        if (totalLeft <= 0) return json({ error: '密码错误次数过多，该闪照管理功能已永久锁定', locked: true }, 423);
        if (left <= 0) return json({ error: `密码错误次数过多，请 15 分钟后再试（累计还剩 ${totalLeft} 次机会）` }, 429);
        return json({ error: `管理密码错误（本轮还可尝试 ${left} 次，累计剩余 ${totalLeft} 次）` }, 401);
    }
    // 窗口计数在成功后清零；累计计数不清零，防止攻击者借主人登录"续命"
    if (fails > 0) ctx.waitUntil(env.VIEW_RECORDS.delete(failKey));

    const now = Date.now();
    const currentViews = parseInt(await env.VIEW_RECORDS.get(`views:${id}`) || '0');

    if (now >= meta.expiresAt || (meta.maxViews !== 0 && currentViews >= meta.maxViews)) {
        ctx.waitUntil(purgePhoto(env, id));
        return json({ error: '闪照已过期或已达查看上限，已被焚毁', gone: true }, 410);
    }

    // ① 立即焚毁
    if (action === 'delete') {
        await purgePhoto(env, id);
        return json({ ok: true, deleted: true });
    }

    // ② 调整有效期 / 查看人数（不改链接、不改密码）
    if (action === 'update') {
        const next = { ...meta };

        if (body.maxViews !== undefined && body.maxViews !== null) {
            const mv = Number(body.maxViews);
            if (!Number.isInteger(mv) || mv < 0 || mv > 100000) {
                return json({ error: '查看人数需为 1~100000 的整数，或选择「不限」' }, 400);
            }
            if (mv !== 0 && mv <= currentViews) {
                return json({ error: `新上限必须大于已查看人数（当前已有 ${currentViews} 人查看）；如需立即失效请使用「立即焚毁」` }, 400);
            }
            next.maxViews = mv;
        }

        if (body.expiresAt !== undefined && body.expiresAt !== null) {
            const ex = Math.floor(Number(body.expiresAt));
            const limit = meta.createdAt + MAX_LIFETIME_MS;
            if (!Number.isFinite(ex)) return json({ error: '到期时间格式错误' }, 400);
            if (ex < now + 60 * 1000) return json({ error: '到期时间至少要在 1 分钟之后；如需立即失效请使用「立即焚毁」' }, 400);
            if (ex > limit) return json({ error: '到期时间不能晚于上传后 7 天' }, 400);
            next.expiresAt = ex;
        }

        await env.VIEW_RECORDS.put(`meta:${id}`, JSON.stringify(next), { expirationTtl: kvTtl(meta.createdAt) });
        return json({ ok: true, info: buildInfo(obj, next, currentViews) });
    }

    // ③ 查看状态
    return json({ ok: true, info: buildInfo(obj, meta, currentViews) });
}

function buildInfo(obj, meta, views) {
    const cm = obj.customMetadata || {};
    return {
        views,
        maxViews: meta.maxViews,
        createdAt: meta.createdAt,
        expiresAt: meta.expiresAt,
        maxExpiresAt: meta.createdAt + MAX_LIFETIME_MS,
        maxTime: parseInt(cm.maxTime || '5'),
        wechatOnly: cm.wechatOnly === 'true',
        now: Date.now()
    };
}

/**
 * 读取闪照当前生效的规则：优先 KV 中的可变配置（管理页修改后的值），
 * KV 尚未同步 / 旧版闪照时回退到 R2 元数据。
 */
async function loadState(env, id, obj) {
    const cm = obj.customMetadata || {};
    const meta = safeParse(await env.VIEW_RECORDS.get(`meta:${id}`));
    const uploaded = obj.uploaded ? new Date(obj.uploaded).getTime() : Date.now();
    const createdAt = (meta && meta.createdAt) || parseInt(cm.createdAt) || uploaded;
    const maxViews = meta ? meta.maxViews : parseInt(cm.maxViews || '1');
    const expiresAt = meta ? meta.expiresAt : (parseInt(cm.expiresAt) || (createdAt + MAX_LIFETIME_MS));
    return { createdAt, maxViews, expiresAt, expired: Date.now() >= expiresAt };
}

/** 彻底删除一张闪照：R2 原图 + 计数 + 管理配置（密码随之作废） */
async function purgePhoto(env, id) {
    await env.BUCKET.delete(id);
    await Promise.all([
        env.VIEW_RECORDS.delete(`views:${id}`),
        env.VIEW_RECORDS.delete(`meta:${id}`)
    ]);
}

/** 定时清理：已过 7 天的直接删；7 天内的读取 KV 判断是否被提前设置了到期 */
async function cleanupExpired(env) {
    const now = Date.now();
    let cursor;
    let kvBudget = 300;
    do {
        const list = await env.BUCKET.list({ cursor, limit: 500, include: ['customMetadata'] });
        for (const obj of list.objects) {
            const cm = obj.customMetadata || {};
            const createdAt = parseInt(cm.createdAt) || new Date(obj.uploaded).getTime();
            if (now >= createdAt + MAX_LIFETIME_MS) {
                await purgePhoto(env, obj.key);
                continue;
            }
            if (kvBudget-- <= 0) return;
            const state = await loadState(env, obj.key, obj);
            if (state.expired) await purgePhoto(env, obj.key);
        }
        cursor = list.truncated ? list.cursor : undefined;
    } while (cursor);
}

// --- 3. 核心加密与辅助函数 ---

async function getCipherKey(id) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.digest('SHA-256', encoder.encode(id + "_flash_secret_salt_2024"));
    return await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function getUserHash(request) {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const ua = request.headers.get('User-Agent') || 'unknown';
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(ip + ua));
    return toHex(hashBuffer);
}

function generatePassword() {
    const space = 10 ** PWD_DIGITS;                              // 10000
    const limit = Math.floor(0x100000000 / space) * space;       // 拒绝采样，消除取模偏差
    let n;
    do { n = crypto.getRandomValues(new Uint32Array(1))[0]; } while (n >= limit);
    return String(n % space).padStart(PWD_DIGITS, '0');          // 如 0386、7215
}

function formatPassword(p) {
    return p;
}

function normalizePassword(p) {
    return String(p || '').replace(/[^0-9]/g, '').slice(0, 16);
}

async function hashPassword(password, salt) {
    // 4 位数字密码的安全性主要靠「尝试次数限制」保证；哈希仅避免 KV 中出现明文
    const data = new TextEncoder().encode(`${salt}:${password}:${MANAGE_PEPPER}`);
    return toHex(await crypto.subtle.digest('SHA-256', data));
}

function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

function randomHex(bytes) {
    return toHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

function toHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function kvTtl(createdAt) {
    return Math.max(60, Math.ceil((createdAt + MAX_LIFETIME_MS + KV_GRACE_MS - Date.now()) / 1000));
}

function isValidId(id) {
    return typeof id === 'string' && UUID_RE.test(id);
}

function safeParse(raw) {
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return null; }
}

function html(body, extraHeaders = {}) {
    return new Response(body, { headers: { 'Content-Type': 'text/html;charset=UTF-8', ...extraHeaders } });
}

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
    });
}

function errorPage(message) {
    return new Response(`
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover" />
            <title>提示</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-black text-white h-screen flex flex-col items-center justify-center select-none" oncontextmenu="return false;">
            <div class="text-xl font-bold text-center px-6 tracking-wide leading-relaxed">${message}</div>
            <button onclick="window.location.href='/'" class="mt-8 px-8 py-3 bg-white/10 hover:bg-white/20 active:scale-95 transition-all border border-white/20 rounded-2xl text-sm font-bold tracking-wider backdrop-blur-md">我也要发闪照</button>
        </body>
        </html>
    `, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

// --- 4. 前端内嵌 HTML (纯字符串形式返回) ---

const htmlIndex = `
<!DOCTYPE html>
<html lang="zh-CN" class="antialiased">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover" />
    <title>闪照发送</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/heic2any@0.0.4/dist/heic2any.min.js"></script>
    <script>
        tailwind.config = { darkMode: 'class' };
        
        let currentTheme = localStorage.getItem('theme') || 'auto';
        function applyTheme(theme) {
            if (theme === 'dark' || (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                document.documentElement.classList.add('dark');
            } else {
                document.documentElement.classList.remove('dark');
            }
        }
        applyTheme(currentTheme);
        
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
            if (currentTheme === 'auto') applyTheme('auto');
        });
    </script>
</head>
<body class="bg-gray-100 dark:bg-gray-900 min-h-screen p-4 flex flex-col items-center justify-center font-sans transition-colors duration-300">
    
    <button id="themeToggle" class="fixed top-4 left-4 p-2.5 rounded-full bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-300 shadow-md border border-gray-100 dark:border-gray-700 hover:scale-105 active:scale-95 transition-all z-50" title="切换主题">
        <svg id="icon-auto" class="w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
        <svg id="icon-sun" class="w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
        <svg id="icon-moon" class="w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
    </button>

    <div class="bg-white dark:bg-gray-800 w-full max-w-md rounded-3xl shadow-xl p-7 space-y-5 transition-colors duration-300 border border-transparent dark:border-gray-700">
        <h1 class="text-2xl font-black text-gray-800 dark:text-white text-center tracking-wider mb-2 transition-colors">🔥 阅后即焚</h1>
        
        <form id="uploadForm" class="space-y-4">
            <div>
                <label class="block text-sm font-bold text-gray-700 dark:text-gray-300 mb-2 transition-colors">选择图片</label>
                <input type="file" id="file" accept="image/*,.heic,.heif" class="w-full text-sm text-gray-500 dark:text-gray-400 file:mr-4 file:py-3 file:px-4 file:rounded-xl file:border-0 file:text-sm file:font-semibold file:bg-blue-50 dark:file:bg-blue-900/40 file:text-blue-700 dark:file:text-blue-400 hover:file:bg-blue-100 dark:hover:file:bg-blue-900/60 min-h-[44px] transition-colors" required>
            </div>
            
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm font-bold text-gray-700 dark:text-gray-300 mb-2 transition-colors">单次阅读时间</label>
                    <select id="maxTime" class="w-full border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-xl p-3 min-h-[44px] focus:ring-2 focus:ring-blue-500 outline-none transition-colors">
                        <option value="3">3 秒</option>
                        <option value="5" selected>5 秒</option>
                        <option value="10">10 秒</option>
                    </select>
                </div>

                <div class="relative">
                    <div class="flex items-center justify-between mb-2">
                        <label class="block text-sm font-bold text-gray-700 dark:text-gray-300 transition-colors">允许总查看人数</label>
                        <label class="flex items-center text-xs font-bold text-blue-500 cursor-pointer select-none">
                            <input type="checkbox" id="unlimitedViews" class="mr-1.5 w-3.5 h-3.5 accent-blue-500"> 不限
                        </label>
                    </div>
                    <input type="number" id="maxViews" value="1" min="1" class="w-full border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-xl p-3 min-h-[44px] focus:ring-2 focus:ring-blue-500 outline-none text-center transition-colors disabled:opacity-80 disabled:bg-gray-100 dark:disabled:bg-gray-800">
                </div>
            </div>

            <div class="space-y-2.5 p-4 rounded-2xl border border-gray-100 dark:border-gray-700 transition-colors">
                <div class="flex items-center justify-between">
                    <label for="expireInput" class="block text-sm font-bold text-gray-700 dark:text-gray-300 transition-colors">链接有效期至</label>
                    <span class="text-[11px] text-gray-400 dark:text-gray-500">上传后可调 · 最长 7 天</span>
                </div>
                <div class="flex flex-wrap gap-2">
                    <button type="button" data-sec="600" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">10 分钟</button>
                    <button type="button" data-sec="3600" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">1 小时</button>
                    <button type="button" data-sec="21600" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">6 小时</button>
                    <button type="button" data-sec="86400" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">1 天</button>
                    <button type="button" data-sec="259200" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">3 天</button>
                    <button type="button" data-sec="604800" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">最长 (7天)</button>
                </div>
                <input type="datetime-local" id="expireInput" class="w-full border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 dark:[color-scheme:dark] rounded-xl p-3 min-h-[44px] text-sm focus:ring-2 focus:ring-blue-500 outline-none transition-colors">
                <p id="expireLimitHint" class="text-[11px] text-gray-400 dark:text-gray-500"></p>
            </div>

            <div class="flex items-center justify-between bg-gray-50 dark:bg-gray-700 p-4 rounded-xl border border-gray-100 dark:border-gray-600 mt-2 transition-colors">
                <label class="text-sm font-bold text-gray-700 dark:text-gray-300 select-none transition-colors" for="wechatOnly">仅限微信内查看</label>
                <label class="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" id="wechatOnly" class="sr-only peer">
                    <div class="w-11 h-6 bg-gray-300 dark:bg-gray-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-500"></div>
                </label>
            </div>

            <div id="progressBox" class="hidden mt-2">
                <div class="flex justify-between mb-1">
                    <span id="progressText" class="text-xs font-bold text-blue-600 dark:text-blue-400">正在准备上传...</span>
                    <span id="progressPercent" class="text-xs font-bold text-blue-600 dark:text-blue-400">0%</span>
                </div>
                <div class="w-full bg-blue-50 dark:bg-blue-900/30 rounded-full h-2">
                    <div id="progressBar" class="bg-blue-500 h-2 rounded-full transition-all duration-200" style="width: 0%"></div>
                </div>
            </div>

            <button type="submit" id="submitBtn" class="w-full bg-black dark:bg-white text-white dark:text-black rounded-xl py-3.5 font-bold hover:bg-gray-800 dark:hover:bg-gray-200 transition min-h-[44px] active:scale-95 mt-2 shadow-lg shadow-black/10 dark:shadow-white/10">安全加密并上传</button>
        </form>

        <div id="result" class="hidden mt-4 pt-4 border-t border-gray-100 dark:border-gray-700">
            <p class="text-sm font-bold text-green-600 dark:text-green-400 mb-3 flex items-center gap-1 transition-colors">
                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path></svg>
                加密上传完成，这是您的专属链接：
            </p>
            <input type="text" id="shareUrl" readonly class="w-full bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 p-3 rounded-xl mb-3 min-h-[44px] text-sm text-gray-700 dark:text-gray-300 outline-none transition-colors">
            <button id="copyBtn" class="w-full bg-green-500 dark:bg-green-600 text-white rounded-xl py-3.5 font-bold hover:bg-green-600 dark:hover:bg-green-700 transition min-h-[44px] active:scale-95 shadow-lg shadow-green-500/30">一键复制链接</button>
            <p id="expireHint" class="text-xs text-gray-400 dark:text-gray-500 text-center mt-2"></p>

            <div class="mt-5 p-4 rounded-2xl border border-amber-200 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-900/20 space-y-3 transition-colors">
                <div class="flex items-center justify-between">
                    <span class="text-sm font-bold text-amber-700 dark:text-amber-400">🔑 专属管理密码</span>
                    <span class="text-[11px] font-bold text-red-500 dark:text-red-400">仅显示这一次</span>
                </div>
                <div id="managePwd" class="font-mono text-4xl font-black tracking-[0.4em] pl-[0.4em] text-center text-gray-900 dark:text-white bg-white dark:bg-gray-900 rounded-xl py-3 border border-amber-100 dark:border-gray-700 select-all"></div>
                <div class="text-xs text-gray-500 dark:text-gray-400 break-all">管理入口：<a id="manageLink" href="#" target="_blank" rel="noopener" class="text-blue-500 underline"></a></div>
                <div class="grid grid-cols-2 gap-2">
                    <button id="copyPwdBtn" type="button" class="bg-amber-500 hover:bg-amber-600 text-white rounded-xl py-3 text-sm font-bold min-h-[44px] active:scale-95 transition">复制密码</button>
                    <button id="copyManageBtn" type="button" class="bg-white dark:bg-gray-800 border border-amber-300 dark:border-amber-500/40 text-amber-700 dark:text-amber-400 rounded-xl py-3 text-sm font-bold min-h-[44px] active:scale-95 transition">复制管理信息</button>
                </div>
                <p class="text-[11px] leading-relaxed text-amber-700/80 dark:text-amber-300/70">凭此密码可随时<b>立即焚毁</b>该闪照，或<b>调整有效期 / 查看人数</b>（原链接不变，密码也不变）。服务器只保存密码的哈希值，丢失后无法找回，请立即保存；<b>请勿把密码和链接一起发给别人</b>。</p>
            </div>
        </div>

        <p class="text-xs text-gray-400 dark:text-gray-400 text-justify mt-6 leading-relaxed bg-gray-50 dark:bg-gray-700/50 p-3 rounded-xl border border-gray-100 dark:border-gray-700 transition-colors">
            <span class="font-bold text-gray-500 dark:text-gray-300">🔒 隐私承诺：</span>文件已在服务器端进行加密存储，后台无法查看。达到最大查看次数、超过设定的有效期（最长 7 天）或被您凭管理密码手动焚毁后，原始图片将被服务器彻底删除。
        </p>
        <a href="/m" class="block text-center text-xs font-bold text-blue-500 hover:text-blue-600 dark:text-blue-400 mt-1">🛠 管理已发出的闪照</a>
    </div>

    <script>
        function updateThemeIcon() {
            document.getElementById('icon-sun').classList.add('hidden');
            document.getElementById('icon-moon').classList.add('hidden');
            document.getElementById('icon-auto').classList.add('hidden');
            if (currentTheme === 'light') document.getElementById('icon-sun').classList.remove('hidden');
            if (currentTheme === 'dark') document.getElementById('icon-moon').classList.remove('hidden');
            if (currentTheme === 'auto') document.getElementById('icon-auto').classList.remove('hidden');
        }
        updateThemeIcon();

        document.getElementById('themeToggle').addEventListener('click', () => {
            if (currentTheme === 'auto') currentTheme = 'light';
            else if (currentTheme === 'light') currentTheme = 'dark';
            else currentTheme = 'auto';
            localStorage.setItem('theme', currentTheme);
            applyTheme(currentTheme);
            updateThemeIcon();
        });

        const maxViewsInput = document.getElementById('maxViews');
        const unlimitedCheck = document.getElementById('unlimitedViews');
        const expireInput = document.getElementById('expireInput');
        const expireLimitHint = document.getElementById('expireLimitHint');
        const presetBtns = Array.from(document.querySelectorAll('.preset'));
        let selectedPresetSec = 604800;
        let lastViews = maxViewsInput.value;
        let lastResult = null;

        function pad2(n) { return (n < 10 ? '0' : '') + n; }
        function fmtTime(ms) {
            const d = new Date(ms);
            return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
        }
        function toLocalInput(ms) {
            const d = new Date(ms);
            return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + 'T' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
        }
        const PRESET_IDLE = ['bg-gray-100', 'dark:bg-gray-700', 'text-gray-600', 'dark:text-gray-300', 'hover:bg-blue-50', 'dark:hover:bg-blue-900/40'];
        const PRESET_ACTIVE = ['bg-blue-500', 'text-white'];
        function highlightPreset(sec) {
            presetBtns.forEach((b) => {
                const match = sec !== null && Number(b.dataset.sec) === sec;
                b.classList.remove(...(match ? PRESET_IDLE : PRESET_ACTIVE));
                b.classList.add(...(match ? PRESET_ACTIVE : PRESET_IDLE));
            });
        }
        function syncExpireBounds() {
            const now = Date.now();
            const maxMs = now + 7 * 86400000;
            expireInput.min = toLocalInput(now + 2 * 60000);
            expireInput.max = toLocalInput(maxMs);
            expireLimitHint.textContent = '支持点选快捷时长或自选时刻，最晚至 ' + fmtTime(maxMs);
            return now;
        }
        function selectPreset(sec) {
            selectedPresetSec = sec;
            const now = syncExpireBounds();
            expireInput.value = toLocalInput(now + sec * 1000);
            highlightPreset(sec);
        }
        presetBtns.forEach((b) => {
            b.addEventListener('click', () => selectPreset(Number(b.dataset.sec)));
        });
        expireInput.addEventListener('focus', syncExpireBounds);
        expireInput.addEventListener('input', () => {
            selectedPresetSec = null;
            highlightPreset(null);
        });
        selectPreset(604800);
        async function copyText(text) {
            try { await navigator.clipboard.writeText(text); return true; } catch (e) {
                const ta = document.createElement('textarea');
                ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
                document.body.appendChild(ta); ta.select();
                let ok = false; try { ok = document.execCommand('copy'); } catch (_) {}
                document.body.removeChild(ta);
                return ok;
            }
        }
        function flashBtn(btn, text) {
            if (!btn.dataset.label) btn.dataset.label = btn.textContent;
            btn.textContent = text;
            setTimeout(() => { btn.textContent = btn.dataset.label; }, 2000);
        }
        document.getElementById('copyPwdBtn').addEventListener('click', async (e) => {
            if (!lastResult) return;
            flashBtn(e.currentTarget, (await copyText(lastResult.password)) ? '已复制 ✓' : '复制失败，请手动选择');
        });
        document.getElementById('copyManageBtn').addEventListener('click', async (e) => {
            if (!lastResult) return;
            const text = ['【闪照管理信息 · 请自己保存，勿外发】', '闪照链接：' + lastResult.url, '管理入口：' + lastResult.manageUrl, '管理密码：' + lastResult.password].join('\\n');
            flashBtn(e.currentTarget, (await copyText(text)) ? '已复制 ✓' : '复制失败，请手动选择');
        });

        unlimitedCheck.addEventListener('change', (e) => {
            if (e.target.checked) {
                lastViews = maxViewsInput.value;
                maxViewsInput.type = 'text';
                maxViewsInput.value = '不限人数 (按有效期焚毁)';
                maxViewsInput.disabled = true;
                maxViewsInput.classList.add('text-blue-500', 'font-bold', 'text-sm');
            } else {
                maxViewsInput.type = 'number';
                maxViewsInput.value = lastViews || '1';
                maxViewsInput.disabled = false;
                maxViewsInput.classList.remove('text-blue-500', 'font-bold', 'text-sm');
            }
        });

        document.getElementById('uploadForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submitBtn');
            const progressBox = document.getElementById('progressBox');
            const progressBar = document.getElementById('progressBar');
            const progressText = document.getElementById('progressText');
            const progressPercent = document.getElementById('progressPercent');
            
            btn.disabled = true;
            document.getElementById('result').classList.add('hidden');
            progressBox.classList.remove('hidden');

            let uploadFile = document.getElementById('file').files[0];

            if (uploadFile.size > 20 * 1024 * 1024) {
                alert('文件大小不能超过 20MB，请压缩或重新选择');
                resetUI();
                return;
            }

            let customTs = null;
            if (selectedPresetSec === null) {
                customTs = expireInput.value ? new Date(expireInput.value).getTime() : NaN;
                const now = Date.now();
                if (!customTs || isNaN(customTs)) {
                    alert('请选择有效的到期时间');
                    resetUI();
                    return;
                }
                if (customTs < now + 60000) {
                    alert('到期时间至少要在 1 分钟之后');
                    resetUI();
                    return;
                }
                if (customTs > now + 7 * 86400000) {
                    alert('到期时间不能超过上传后 7 天');
                    resetUI();
                    return;
                }
            }

            // 💡 核心修复：全面覆盖 .heic 和 .heif 以及大写情况，兼容空 MIME Type
            const fileName = uploadFile.name.toLowerCase();
            const fileType = uploadFile.type.toLowerCase();
            if (fileType.includes('heic') || fileType.includes('heif') || fileName.endsWith('.heic') || fileName.endsWith('.heif')) {
                btn.textContent = '设备兼容处理中...';
                progressText.textContent = '正在转换苹果/高效率格式...';
                progressBar.classList.replace('bg-blue-500', 'bg-yellow-500');
                progressBar.style.width = '50%';
                progressPercent.textContent = '...';
                
                try {
                    const convertedBlob = await heic2any({ blob: uploadFile, toType: "image/jpeg", quality: 0.8 });
                    const finalBlob = Array.isArray(convertedBlob) ? convertedBlob[0] : convertedBlob;
                    // 使用正则安全替换后缀名
                    uploadFile = new File([finalBlob], uploadFile.name.replace(/\\.(heic|heif)$/i, ".jpg"), { type: "image/jpeg" });
                } catch (err) {
                    alert('原生高效率照片转换失败，请尝试选择其他图片格式');
                    resetUI();
                    return;
                }
            }

            btn.textContent = '加密上传中...';
            progressBar.classList.replace('bg-yellow-500', 'bg-blue-500');
            progressText.textContent = '正在安全加密并传输...';
            progressBar.style.width = '0%';
            progressPercent.textContent = '0%';

            const formData = new FormData();
            formData.append('file', uploadFile);
            formData.append('maxTime', document.getElementById('maxTime').value);
            const finalMaxViews = unlimitedCheck.checked ? '0' : document.getElementById('maxViews').value;
            formData.append('maxViews', finalMaxViews);
            formData.append('wechatOnly', document.getElementById('wechatOnly').checked);
            if (selectedPresetSec !== null) {
                formData.append('expiresIn', String(selectedPresetSec));
            } else if (customTs !== null) {
                formData.append('expiresAt', String(customTs));
            }

            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/upload', true);

            xhr.upload.onprogress = (event) => {
                if (event.lengthComputable) {
                    const percentComplete = Math.round((event.loaded / event.total) * 100);
                    progressBar.style.width = percentComplete + '%';
                    progressPercent.textContent = percentComplete + '%';
                }
            };

            xhr.onload = () => {
                if (xhr.status === 200) {
                    const data = JSON.parse(xhr.responseText);
                    lastResult = data;
                    document.getElementById('result').classList.remove('hidden');
                    document.getElementById('shareUrl').value = data.url;
                    document.getElementById('managePwd').textContent = data.password;
                    const ml = document.getElementById('manageLink');
                    ml.href = data.manageUrl;
                    ml.textContent = data.manageUrl;
                    document.getElementById('expireHint').textContent = '有效期至 ' + fmtTime(data.expiresAt) + '，可凭管理密码随时调整或提前焚毁';
                    
                    progressBox.classList.add('hidden');
                    btn.textContent = '上传成功 (再次点击可上传新图)';
                    btn.disabled = false;
                } else if (xhr.status === 413) {
                    alert('文件过大，超出 20MB 限制');
                    resetUI();
                } else {
                    let msg = '上传失败，请重试';
                    try { const errData = JSON.parse(xhr.responseText); if (errData && errData.error) msg = errData.error; } catch (e) {}
                    alert(msg);
                    resetUI();
                }
            };

            xhr.onerror = () => {
                alert('网络连接错误，上传失败');
                resetUI();
            };

            xhr.send(formData);

            function resetUI() {
                btn.textContent = '安全加密并上传';
                btn.disabled = false;
                progressBox.classList.add('hidden');
            }
        });

        document.getElementById('copyBtn').addEventListener('click', () => {
            const urlInput = document.getElementById('shareUrl');
            urlInput.select();
            document.execCommand('copy');
            const btn = document.getElementById('copyBtn');
            btn.textContent = '已复制，快去粘贴发送吧！';
            
            btn.classList.remove('bg-green-500', 'dark:bg-green-600', 'shadow-green-500/30');
            btn.classList.add('bg-gray-800', 'dark:bg-gray-700');
            setTimeout(() => {
                btn.textContent = '一键复制链接';
                btn.classList.remove('bg-gray-800', 'dark:bg-gray-700');
                btn.classList.add('bg-green-500', 'dark:bg-green-600', 'shadow-green-500/30');
            }, 3000);
        });
    </script>
</body>
</html>
`;

const htmlViewer = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover" />
    <title>阅后即焚</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            overscroll-behavior: none;
            -webkit-touch-callout: none;
            -webkit-user-select: none;
            user-select: none;
        }
        .safe-media {
            pointer-events: none;
            user-drag: none;
            -webkit-user-drag: none;
            object-fit: contain;
            width: 100%;
            height: 100%;
        }
    </style>
</head>
<body class="bg-black text-white h-[100dvh] w-screen overflow-hidden flex flex-col items-center justify-center m-0 p-0" oncontextmenu="return false;">
    
    <div id="container" class="w-full h-full flex flex-col items-center justify-center relative">
        <div id="loading" class="text-sm font-bold tracking-widest text-gray-400 animate-pulse">正在安全解密数据...</div>

        <div id="interactiveArea" class="hidden absolute inset-0 w-full h-full bg-gray-900">
            <div id="tipLayer" class="absolute inset-0 z-10 flex flex-col items-center justify-center pointer-events-none backdrop-blur-xl bg-black/60 transition-opacity">
                <div class="bg-white/10 px-8 py-4 rounded-3xl backdrop-blur-md text-center border border-white/10 shadow-2xl">
                    <p class="text-xl font-bold tracking-widest mb-1">长按屏幕查看</p>
                    <p class="text-xs text-gray-400">松手即刻销毁</p>
                </div>
            </div>

            <div id="touchTarget" class="absolute inset-0 z-20 cursor-pointer touch-none flex items-center justify-center"></div>
            
            <div id="timerBox" class="hidden absolute top-6 right-6 w-12 h-12 bg-black/50 backdrop-blur-md border border-white/20 rounded-xl z-50 flex items-center justify-center pointer-events-none shadow-lg">
                <span id="countdown" class="text-white font-mono text-2xl font-bold"></span>
            </div>
        </div>
    </div>

    <script>
        const id = '{{ID}}';
        let mediaBlob = null;
        let mediaType = 'image/jpeg';
        let maxTime = 5;
        let timer = null;
        let isViewed = false;
        let objectUrl = null;

        async function init() {
            try {
                const res = await fetch('/api/img/' + id);
                if (!res.ok) {
                    window.location.reload(); 
                    return;
                }
                maxTime = parseInt(res.headers.get('x-max-time')) || 5;
                mediaType = res.headers.get('Content-Type') || 'image/jpeg';
                mediaBlob = new Blob([await res.arrayBuffer()], { type: mediaType });

                document.getElementById('loading').classList.add('hidden');
                document.getElementById('interactiveArea').classList.remove('hidden');
            } catch (e) {
                document.getElementById('container').innerHTML = '<div class="text-xl font-bold">⚠️ 网络异常，数据加载失败</div>';
            }
        }
        init();

        const touchTarget = document.getElementById('touchTarget');
        const tipLayer = document.getElementById('tipLayer');
        const timerBox = document.getElementById('timerBox');
        const countdownSpan = document.getElementById('countdown');
        let mediaEl = null;

        const startView = (e) => {
            if (e && e.type !== 'blur' && e.type !== 'visibilitychange') {
                e.preventDefault();
            }
            if (isViewed || !mediaBlob) return;
            isViewed = true; 

            fetch('/api/mark/' + id, { method: 'POST' }).catch(()=>{});

            tipLayer.classList.add('hidden');
            timerBox.classList.remove('hidden');
            countdownSpan.innerText = maxTime;

            objectUrl = URL.createObjectURL(mediaBlob);

            mediaEl = document.createElement('img');
            mediaEl.src = objectUrl;
            mediaEl.className = 'safe-media';
            touchTarget.appendChild(mediaEl);

            let timeLeft = maxTime;
            timer = setInterval(() => {
                timeLeft--;
                countdownSpan.innerText = timeLeft;
                if (timeLeft <= 0) destroy();
            }, 1000);
        };

        const destroy = (e) => {
            if (e && e.type !== 'blur' && e.type !== 'visibilitychange') {
                e.preventDefault();
            }
            if (!isViewed) return;
            
            if (timer) clearInterval(timer);
            if (objectUrl) {
                URL.revokeObjectURL(objectUrl);
                objectUrl = null;
            }
            timerBox.classList.add('hidden');
            
            document.getElementById('container').innerHTML = \`
                <div class="flex flex-col items-center justify-center space-y-8 animate-fade-in">
                    <div class="text-2xl font-bold tracking-widest text-red-500">⚠️ 文件已不可查看</div>
                    <button onclick="window.location.href='/'" class="px-8 py-3.5 bg-white/10 hover:bg-white/20 active:scale-95 transition-all border border-white/20 rounded-2xl text-sm font-bold tracking-wider backdrop-blur-md shadow-lg">我也要发闪照 📸</button>
                </div>
            \`;
            mediaBlob = null;
            isViewed = false;
        };

        // --- 常规交互监听 ---
        touchTarget.addEventListener('mousedown', startView);
        touchTarget.addEventListener('touchstart', startView, { passive: false });
        window.addEventListener('mouseup', destroy);
        window.addEventListener('touchend', destroy);
        window.addEventListener('touchcancel', destroy);

        // --- 🛡️ PC 端防截屏强力屏障 ---
        
        window.addEventListener('blur', destroy);
        window.addEventListener('mouseleave', destroy);
        window.addEventListener('pagehide', destroy);
        window.addEventListener('visibilitychange', () => {
            if (document.hidden) destroy();
        });

        window.addEventListener('keydown', (e) => {
            if (e.key === 'PrintScreen' || e.keyCode === 44) {
                destroy(); 
                e.preventDefault();
            }
            if (e.key === 'F12' || e.keyCode === 123) {
                destroy();
                e.preventDefault();
            }
            if (e.ctrlKey || e.metaKey) {
                const key = e.key.toLowerCase();
                if (['s', 'p', 'c', 'shift'].includes(key)) {
                    destroy();
                    e.preventDefault();
                }
            }
        });
    </script>
</body>
</html>
`;

const htmlManage = `
<!DOCTYPE html>
<html lang="zh-CN" class="antialiased">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover" />
    <meta name="robots" content="noindex, nofollow">
    <title>闪照管理</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = { darkMode: 'class' };
        let currentTheme = localStorage.getItem('theme') || 'auto';
        function applyTheme(theme) {
            if (theme === 'dark' || (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                document.documentElement.classList.add('dark');
            } else {
                document.documentElement.classList.remove('dark');
            }
        }
        applyTheme(currentTheme);
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
            if (currentTheme === 'auto') applyTheme('auto');
        });
    </script>
</head>
<body class="bg-gray-100 dark:bg-gray-900 min-h-screen p-4 flex flex-col items-center justify-center font-sans transition-colors duration-300">

    <button id="themeToggle" class="fixed top-4 left-4 p-2.5 rounded-full bg-white dark:bg-gray-800 text-gray-600 dark:text-gray-300 shadow-md border border-gray-100 dark:border-gray-700 hover:scale-105 active:scale-95 transition-all z-50" title="切换主题">
        <svg id="icon-auto" class="w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
        <svg id="icon-sun" class="w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
        <svg id="icon-moon" class="w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
    </button>

    <div class="bg-white dark:bg-gray-800 w-full max-w-md rounded-3xl shadow-xl p-7 space-y-5 transition-colors duration-300 border border-transparent dark:border-gray-700">
        <h1 class="text-2xl font-black text-gray-800 dark:text-white text-center tracking-wider mb-2">🛠 闪照管理</h1>

        <div id="msg" class="hidden text-sm font-bold rounded-xl px-4 py-3 leading-relaxed"></div>

        <!-- 登录 -->
        <form id="loginForm" class="space-y-4" autocomplete="off">
            <div id="idField">
                <label class="block text-sm font-bold text-gray-700 dark:text-gray-300 mb-2">闪照链接</label>
                <input id="linkInput" type="text" placeholder="粘贴闪照链接或管理链接" class="w-full border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-xl p-3 min-h-[44px] text-sm focus:ring-2 focus:ring-blue-500 outline-none">
            </div>
            <div id="idShow" class="hidden text-xs text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-gray-700/50 rounded-xl px-3 py-2 break-all font-mono"></div>
            <div>
                <label class="block text-sm font-bold text-gray-700 dark:text-gray-300 mb-2">专属管理密码</label>
                <input id="pwdInput" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" spellcheck="false" placeholder="4 位数字" class="w-full border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-xl p-3 min-h-[44px] font-mono text-2xl tracking-[0.5em] text-center focus:ring-2 focus:ring-blue-500 outline-none">
            </div>
            <button type="submit" id="loginBtn" class="w-full bg-black dark:bg-white text-white dark:text-black rounded-xl py-3.5 font-bold hover:bg-gray-800 dark:hover:bg-gray-200 transition min-h-[44px] active:scale-95 shadow-lg">进入管理</button>
            <p class="text-xs text-gray-400 leading-relaxed">每张闪照只能用上传时生成的 4 位专属密码管理。为防止被猜，同一张闪照 15 分钟内输错 5 次会临时锁定，累计输错 20 次将永久锁定管理功能（照片仍按原设置到期）。</p>
        </form>

        <!-- 管理面板 -->
        <div id="panel" class="hidden space-y-5">
            <div class="grid grid-cols-2 gap-3">
                <div class="bg-gray-50 dark:bg-gray-700/60 rounded-2xl p-4 text-center border border-gray-100 dark:border-gray-700">
                    <p class="text-xs text-gray-500 dark:text-gray-400 mb-1">已查看 / 上限</p>
                    <p id="statViews" class="text-xl font-black text-gray-800 dark:text-white"></p>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700/60 rounded-2xl p-4 text-center border border-gray-100 dark:border-gray-700">
                    <p class="text-xs text-gray-500 dark:text-gray-400 mb-1">剩余有效期</p>
                    <p id="statLeft" class="text-xl font-black text-gray-800 dark:text-white"></p>
                </div>
            </div>
            <div class="text-xs text-gray-500 dark:text-gray-400 space-y-1 px-1">
                <div>上传时间：<span id="infoCreated"></span></div>
                <div>到期时间：<span id="infoExpires" class="font-bold text-gray-700 dark:text-gray-200"></span></div>
                <div>单次阅读：<span id="infoMaxTime"></span> · <span id="infoWechat"></span></div>
            </div>

            <div class="space-y-2 p-4 rounded-2xl border border-gray-100 dark:border-gray-700">
                <div class="flex items-center justify-between">
                    <label class="text-sm font-bold text-gray-700 dark:text-gray-300">允许总查看人数</label>
                    <label class="flex items-center text-xs font-bold text-blue-500 cursor-pointer select-none">
                        <input type="checkbox" id="unlimited" class="mr-1.5 w-3.5 h-3.5 accent-blue-500"> 不限
                    </label>
                </div>
                <div class="flex gap-2">
                    <input type="number" id="viewsInput" min="1" class="flex-1 min-w-0 border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-xl p-3 min-h-[44px] text-center focus:ring-2 focus:ring-blue-500 outline-none disabled:opacity-70">
                    <button id="saveViewsBtn" type="button" class="px-5 bg-blue-500 hover:bg-blue-600 text-white rounded-xl font-bold text-sm min-h-[44px] active:scale-95 transition">保存</button>
                </div>
                <p id="viewsHint" class="text-[11px] text-gray-400 leading-relaxed"></p>
            </div>

            <div class="space-y-2 p-4 rounded-2xl border border-gray-100 dark:border-gray-700">
                <label class="block text-sm font-bold text-gray-700 dark:text-gray-300">有效期至</label>
                <div class="flex flex-wrap gap-2">
                    <button type="button" data-h="1" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">1 小时后</button>
                    <button type="button" data-h="6" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">6 小时后</button>
                    <button type="button" data-h="24" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">1 天后</button>
                    <button type="button" data-h="72" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">3 天后</button>
                    <button type="button" data-h="max" class="preset px-3 py-1.5 rounded-lg text-xs font-bold bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-50 dark:hover:bg-blue-900/40 active:scale-95 transition">最长</button>
                </div>
                <div class="flex gap-2">
                    <input type="datetime-local" id="expireInput" class="flex-1 min-w-0 border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-gray-200 dark:[color-scheme:dark] rounded-xl p-3 min-h-[44px] text-sm focus:ring-2 focus:ring-blue-500 outline-none">
                    <button id="saveExpireBtn" type="button" class="px-5 bg-blue-500 hover:bg-blue-600 text-white rounded-xl font-bold text-sm min-h-[44px] active:scale-95 transition">保存</button>
                </div>
                <p class="text-[11px] text-gray-400">可提前或延后，最晚至 <span id="maxExpireText"></span>（上传后 7 天）</p>
            </div>

            <div class="space-y-2 p-4 rounded-2xl border border-red-200 dark:border-red-500/30 bg-red-50/60 dark:bg-red-900/10">
                <button id="deleteBtn" type="button" class="w-full bg-red-500 hover:bg-red-600 text-white rounded-xl py-3.5 font-bold min-h-[44px] active:scale-95 transition shadow-lg shadow-red-500/30">🔥 立即焚毁这张闪照</button>
                <p class="text-[11px] text-red-500/80 dark:text-red-400/80 leading-relaxed">焚毁后图片立即从服务器删除，原链接失效，管理密码同时作废，不可恢复。</p>
            </div>

            <div class="grid grid-cols-2 gap-2">
                <button id="refreshBtn" type="button" class="bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-xl py-3 text-sm font-bold min-h-[44px] active:scale-95 transition">刷新状态</button>
                <button id="logoutBtn" type="button" class="bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-xl py-3 text-sm font-bold min-h-[44px] active:scale-95 transition">退出管理</button>
            </div>
        </div>

        <!-- 已焚毁 -->
        <div id="goneBox" class="hidden text-center space-y-5 py-4">
            <div class="text-5xl">🔥</div>
            <p id="goneText" class="font-bold text-gray-800 dark:text-white leading-relaxed"></p>
            <a href="/" class="inline-block px-8 py-3 bg-black dark:bg-white text-white dark:text-black rounded-xl text-sm font-bold active:scale-95 transition">发一张新闪照</a>
        </div>

        <a href="/" id="homeLink" class="block text-center text-xs font-bold text-blue-500 dark:text-blue-400">← 返回发送页</a>
    </div>

    <script>
        function $(id) { return document.getElementById(id); }

        // ---- 主题 ----
        function updateThemeIcon() {
            ['icon-sun', 'icon-moon', 'icon-auto'].forEach(function (k) { $(k).classList.add('hidden'); });
            $(currentTheme === 'light' ? 'icon-sun' : currentTheme === 'dark' ? 'icon-moon' : 'icon-auto').classList.remove('hidden');
        }
        updateThemeIcon();
        $('themeToggle').addEventListener('click', function () {
            currentTheme = currentTheme === 'auto' ? 'light' : currentTheme === 'light' ? 'dark' : 'auto';
            localStorage.setItem('theme', currentTheme);
            applyTheme(currentTheme);
            updateThemeIcon();
        });

        // ---- 状态 ----
        let photoId = '';
        let password = '';
        let info = null;
        let tick = null;
        let pendingExpire = null;
        let expiring = false;

        function parseId(input) {
            let s = String(input || '').trim();
            ['/v/', '/m/'].forEach(function (p) { const i = s.indexOf(p); if (i >= 0) s = s.slice(i + p.length); });
            s = s.split('?')[0].split('#')[0].split('/')[0].toLowerCase();
            return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s) ? s : '';
        }

        const pathId = parseId(location.pathname);
        if (pathId) {
            $('idField').classList.add('hidden');
            $('idShow').classList.remove('hidden');
            $('idShow').textContent = '闪照 ID：' + pathId;
        }

        // ---- 工具 ----
        function pad(n) { return (n < 10 ? '0' : '') + n; }
        function fmt(ms) {
            const d = new Date(ms);
            return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
        }
        function toLocalInput(ms) {
            const d = new Date(ms);
            return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
        }
        function fmtDuration(ms) {
            const s = Math.max(0, Math.floor(ms / 1000));
            const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
            if (d > 0) return d + '天' + h + '小时';
            if (h > 0) return h + '小时' + m + '分';
            return m + '分' + pad(sec) + '秒';
        }
        function serverNow() { return Date.now() + (info ? info.skew : 0); }

        const MSG_CLASS = {
            error: 'bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-300 border border-red-100 dark:border-red-500/30',
            ok: 'bg-green-50 dark:bg-green-900/30 text-green-600 dark:text-green-300 border border-green-100 dark:border-green-500/30',
            info: 'bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300 border border-blue-100 dark:border-blue-500/30'
        };
        function showMsg(text, type) {
            const el = $('msg');
            el.className = 'text-sm font-bold rounded-xl px-4 py-3 leading-relaxed ' + (MSG_CLASS[type] || MSG_CLASS.info);
            el.textContent = text;
        }
        function hideMsg() { $('msg').className = 'hidden'; }

        function setBusy(btn, busy, text) {
            if (busy) {
                btn.dataset.label = btn.textContent;
                btn.textContent = text;
                btn.disabled = true;
                btn.classList.add('opacity-60');
            } else {
                if (btn.dataset.label) btn.textContent = btn.dataset.label;
                btn.disabled = false;
                btn.classList.remove('opacity-60');
            }
        }

        async function api(action, extra) {
            const body = Object.assign({ action: action, password: password }, extra || {});
            const res = await fetch('/api/manage/' + photoId, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            let data = {};
            try { data = await res.json(); } catch (e) {}
            if (!res.ok) {
                const err = new Error(data.error || ('请求失败（' + res.status + '）'));
                err.gone = !!data.gone;
                throw err;
            }
            return data;
        }

        function handleError(err) {
            if (err && err.gone) showGone(err.message);
            else showMsg((err && err.message) || '网络异常，请重试', 'error');
        }

        function showGone(text) {
            if (tick) clearInterval(tick);
            password = '';
            info = null;
            hideMsg();
            $('loginForm').classList.add('hidden');
            $('panel').classList.add('hidden');
            $('homeLink').classList.add('hidden');
            $('goneBox').classList.remove('hidden');
            $('goneText').textContent = text;
        }

        // ---- 渲染 ----
        function render(i) {
            info = i;
            info.skew = i.now - Date.now();
            pendingExpire = null;

            $('statViews').textContent = i.views + ' / ' + (i.maxViews === 0 ? '不限' : i.maxViews);
            $('infoCreated').textContent = fmt(i.createdAt);
            $('infoExpires').textContent = fmt(i.expiresAt);
            $('infoMaxTime').textContent = i.maxTime + ' 秒';
            $('infoWechat').textContent = i.wechatOnly ? '仅限微信内查看' : '不限查看环境';
            $('maxExpireText').textContent = fmt(i.maxExpiresAt);

            const unlimited = i.maxViews === 0;
            const vi = $('viewsInput');
            $('unlimited').checked = unlimited;
            vi.disabled = unlimited;
            vi.min = i.views + 1;
            vi.value = unlimited ? '' : i.maxViews;
            vi.placeholder = unlimited ? '不限人数' : '';
            $('viewsHint').textContent = '已有 ' + i.views + ' 人查看，新上限需大于 ' + i.views + '；「不限」表示有效期内任何人都可查看（每人仅一次）。';

            const ei = $('expireInput');
            ei.min = toLocalInput(serverNow() + 2 * 60000);
            ei.max = toLocalInput(i.maxExpiresAt);
            ei.value = toLocalInput(i.expiresAt);

            updateLeft();
            if (tick) clearInterval(tick);
            tick = setInterval(updateLeft, 1000);
        }

        function updateLeft() {
            if (!info) return;
            const left = info.expiresAt - serverNow();
            if (left <= 0) {
                clearInterval(tick);
                $('statLeft').textContent = '已到期';
                if (!expiring) {
                    expiring = true;
                    // 触发服务器端焚毁并展示结果
                    api('info').then(function (d) { render(d.info); }).catch(handleError).finally(function () { expiring = false; });
                }
                return;
            }
            $('statLeft').textContent = fmtDuration(left);
        }

        // ---- 登录 ----
        $('loginForm').addEventListener('submit', async function (e) {
            e.preventDefault();
            const id = pathId || parseId($('linkInput').value);
            if (!id) return showMsg('请粘贴正确的闪照链接（形如 /v/xxxxxxxx-xxxx-...）', 'error');
            const pwd = $('pwdInput').value.replace(/[^0-9]/g, '');
            if (pwd.length !== 4) return showMsg('请输入 4 位数字管理密码', 'error');

            photoId = id;
            password = pwd;
            const btn = $('loginBtn');
            setBusy(btn, true, '验证中...');
            try {
                const data = await api('info');
                hideMsg();
                $('loginForm').classList.add('hidden');
                $('panel').classList.remove('hidden');
                render(data.info);
            } catch (err) {
                password = '';
                handleError(err);
            } finally {
                setBusy(btn, false);
            }
        });

        // ---- 修改查看人数 ----
        $('unlimited').addEventListener('change', function (e) {
            const vi = $('viewsInput');
            if (e.target.checked) {
                vi.dataset.last = vi.value;
                vi.value = '';
                vi.placeholder = '不限人数';
                vi.disabled = true;
            } else {
                vi.disabled = false;
                vi.placeholder = '';
                vi.value = vi.dataset.last || (info ? info.views + 1 : 1);
            }
        });

        async function doUpdate(payload, btn, okText) {
            setBusy(btn, true, '保存中...');
            try {
                const data = await api('update', payload);
                render(data.info);
                showMsg('✅ ' + okText + '，原链接与密码均不变（全球节点同步约需 1 分钟）', 'ok');
            } catch (err) {
                handleError(err);
            } finally {
                setBusy(btn, false);
            }
        }

        $('saveViewsBtn').addEventListener('click', function () {
            if (!info) return;
            let mv = 0;
            if (!$('unlimited').checked) {
                mv = parseInt($('viewsInput').value, 10);
                if (!mv || mv < 1) return showMsg('请输入有效的查看人数', 'error');
                if (mv <= info.views) return showMsg('新上限必须大于已查看人数（' + info.views + '）；如需立即失效请使用「立即焚毁」', 'error');
            }
            doUpdate({ maxViews: mv }, $('saveViewsBtn'), '查看人数已更新为 ' + (mv === 0 ? '不限' : mv + ' 人'));
        });

        // ---- 修改有效期 ----
        document.querySelectorAll('.preset').forEach(function (b) {
            b.addEventListener('click', function () {
                if (!info) return;
                const h = b.getAttribute('data-h');
                let target = h === 'max' ? info.maxExpiresAt : serverNow() + Number(h) * 3600000;
                if (target > info.maxExpiresAt) {
                    target = info.maxExpiresAt;
                    showMsg('已超出上传后 7 天的上限，自动调整为最长期限', 'info');
                }
                pendingExpire = target;
                $('expireInput').value = toLocalInput(target);
            });
        });
        $('expireInput').addEventListener('input', function () { pendingExpire = null; });

        $('saveExpireBtn').addEventListener('click', function () {
            if (!info) return;
            const v = $('expireInput').value;
            const target = pendingExpire || (v ? new Date(v).getTime() : NaN);
            if (!target || isNaN(target)) return showMsg('请选择到期时间', 'error');
            if (target < serverNow() + 60000) return showMsg('到期时间至少要在 1 分钟之后；如需立即失效请使用「立即焚毁」', 'error');
            if (target > info.maxExpiresAt) return showMsg('到期时间不能晚于 ' + fmt(info.maxExpiresAt), 'error');
            doUpdate({ expiresAt: target }, $('saveExpireBtn'), '有效期已调整至 ' + fmt(target));
        });

        // ---- 立即焚毁 ----
        $('deleteBtn').addEventListener('click', async function () {
            if (!confirm('确定立即焚毁这张闪照吗？图片将从服务器彻底删除，原链接与管理密码同时失效，且不可恢复。')) return;
            const btn = $('deleteBtn');
            setBusy(btn, true, '焚毁中...');
            try {
                await api('delete');
                showGone('闪照已彻底焚毁，原链接与管理密码均已失效');
            } catch (err) {
                handleError(err);
                setBusy(btn, false);
            }
        });

        // ---- 刷新 / 退出 ----
        $('refreshBtn').addEventListener('click', async function () {
            const btn = $('refreshBtn');
            setBusy(btn, true, '刷新中...');
            try {
                const data = await api('info');
                render(data.info);
                showMsg('状态已刷新', 'info');
            } catch (err) {
                handleError(err);
            } finally {
                setBusy(btn, false);
            }
        });

        $('logoutBtn').addEventListener('click', function () {
            if (tick) clearInterval(tick);
            password = '';
            info = null;
            hideMsg();
            $('pwdInput').value = '';
            $('panel').classList.add('hidden');
            $('loginForm').classList.remove('hidden');
        });
    </script>
</body>
</html>
`;
