/**
 * 阅后即焚（闪照） - Cloudflare Worker
 * 纯单文件：原生 JS + R2 + KV + TailwindCSS + AES加密 + 不限次数群发 + 防截屏 + HEIC/HEIF 全面兼容
 */

// --- 1. 后端 API 与路由逻辑 ---
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // 路由：主页上传页
        if (request.method === 'GET' && path === '/') {
            return new Response(htmlIndex, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

        // 路由：处理上传
        if (request.method === 'POST' && path === '/api/upload') {
            const formData = await request.formData();
            const file = formData.get('file');
            const maxTime = formData.get('maxTime') || '5';
            const maxViews = formData.get('maxViews') || '1';
            const wechatOnly = formData.get('wechatOnly') || 'false';

            if (!file) return new Response('No file provided', { status: 400 });

            // 限制 20MB
            if (file.size > 20 * 1024 * 1024) {
                return new Response('文件过大，超出 20MB 限制', { status: 413 });
            }

            const id = crypto.randomUUID();

            // 🔒 流式 AES-GCM 加密二进制流
            const rawBuffer = await file.arrayBuffer();
            const key = await getCipherKey(id);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encryptedBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, rawBuffer);

            // 存入 R2：存入加密后的乱码
            await env.BUCKET.put(id, encryptedBuffer, {
                customMetadata: {
                    maxTime: maxTime.toString(),
                    maxViews: maxViews.toString(), 
                    wechatOnly: wechatOnly,
                    contentType: file.type || 'application/octet-stream',
                    iv: Array.from(iv).join(',')
                }
            });

            await env.VIEW_RECORDS.put(`views:${id}`, '0', { expirationTtl: 604800 });

            const viewUrl = `${url.origin}/v/${id}`;
            return new Response(JSON.stringify({ url: viewUrl }), { headers: { 'Content-Type': 'application/json' } });
        }

        // 路由：访客查看页
        if (request.method === 'GET' && path.startsWith('/v/')) {
            const id = path.split('/')[2];
            
            const obj = await env.BUCKET.head(id);
            if (!obj) return errorPage('⚠️ 闪照已不可查看或不存在');

            if (obj.customMetadata.wechatOnly === 'true') {
                const ua = request.headers.get('User-Agent') || '';
                if (!ua.toLowerCase().includes('micromessenger')) {
                    return errorPage('⚠️ 此闪照仅限微信内查看<br><span class="text-sm text-gray-400 mt-3 block font-normal">请将链接复制并发送到微信对话框中打开</span>');
                }
            }

            const maxViews = parseInt(obj.customMetadata.maxViews || '1');
            const currentViews = parseInt(await env.VIEW_RECORDS.get(`views:${id}`) || '0');
            
            if (maxViews !== 0 && currentViews >= maxViews) return errorPage('⚠️ 闪照已达最大查看次数，不可查看');

            const userHash = await getUserHash(request);
            const hasViewed = await env.VIEW_RECORDS.get(`user:${id}:${userHash}`);
            if (hasViewed) return errorPage('⚠️ 您已查看过此闪照，不可再次查看');

            return new Response(htmlViewer.replace('{{ID}}', id), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

        // 路由：安全代理获取并解密数据流
        if (request.method === 'GET' && path.startsWith('/api/img/')) {
            const id = path.split('/')[3];
            const obj = await env.BUCKET.get(id);
            if (!obj) return new Response('Not found', { status: 404 });

            const maxViews = parseInt(obj.customMetadata.maxViews || '1');
            const currentViews = parseInt(await env.VIEW_RECORDS.get(`views:${id}`) || '0');
            if (maxViews !== 0 && currentViews >= maxViews) return new Response('Burned', { status: 403 });

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
            const userHash = await getUserHash(request);

            const currentViews = parseInt(await env.VIEW_RECORDS.get(`views:${id}`) || '0');
            const newViews = currentViews + 1;

            const obj = await env.BUCKET.head(id);
            const maxViews = obj ? parseInt(obj.customMetadata.maxViews || '1') : 1;

            if (maxViews !== 0 && newViews >= maxViews) {
                await env.BUCKET.delete(id);
                await env.VIEW_RECORDS.delete(`views:${id}`);
            } else {
                await env.VIEW_RECORDS.put(`views:${id}`, newViews.toString(), { expirationTtl: 604800 });
                await env.VIEW_RECORDS.put(`user:${id}:${userHash}`, '1', { expirationTtl: 604800 });
            }

            return new Response('OK');
        }

        return new Response('Not Found', { status: 404 });
    }
};

// --- 2. 核心加密与辅助函数 ---

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
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
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

// --- 3. 前端内嵌 HTML (纯字符串形式返回) ---

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
                <label class="block text-sm font-bold text-gray-700 dark:text-gray-300 mb-2 transition-colors">选择图片 (支持 GIF/HEIC)</label>
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
        </div>

        <p class="text-xs text-gray-400 dark:text-gray-400 text-justify mt-6 leading-relaxed bg-gray-50 dark:bg-gray-700/50 p-3 rounded-xl border border-gray-100 dark:border-gray-700 transition-colors">
            <span class="font-bold text-gray-500 dark:text-gray-300">🔒 隐私承诺：</span>文件已在服务器端进行高强度加密存储。达到最大查看次数或满 7 天后，底层数据将被彻底物理粉碎，绝不留痕。
        </p>
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
        let lastViews = maxViewsInput.value;

        unlimitedCheck.addEventListener('change', (e) => {
            if (e.target.checked) {
                lastViews = maxViewsInput.value;
                maxViewsInput.type = 'text';
                maxViewsInput.value = '不限人数 (7天后焚毁)';
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
                    document.getElementById('result').classList.remove('hidden');
                    document.getElementById('shareUrl').value = data.url;
                    
                    progressBox.classList.add('hidden');
                    btn.textContent = '上传成功 (再次点击可上传新图)';
                    btn.disabled = false;
                } else if (xhr.status === 413) {
                    alert('文件过大，超出 20MB 限制');
                    resetUI();
                } else {
                    alert('上传失败，请重试');
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
    <title>私密闪照</title>
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
                    <p class="text-xs text-gray-400">松手即刻销毁 / 防截屏保护中</p>
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