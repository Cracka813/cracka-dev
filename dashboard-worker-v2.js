/*  Cracka.dev — Dashboard API Worker v2  (Cloudflare D1 private store)
 *
 *  DATA MODEL:
 *   • Cloudflare D1 (binding `DB`, table `licenses`) = PRIVATE source of truth — full customer records.
 *   • GitHub Cracka_Suite_License.json = PUBLIC keys-only projection [{key,active,tools}] for the
 *     distributed suite tools + bots. Contains NO PII.
 *
 *  ACCESS:
 *   • GET /api/licenses
 *       - admin (Discord id in ADMIN_IDS)         → ALL records (full)
 *       - logged-in non-admin (customer)          → ONLY their own record(s) (discord_id == session id)
 *       - not logged in                           → 403
 *   • POST/PATCH /api/licenses  → admin only  → upsert D1 + publish keys-only feed
 *   • POST /api/issue           → X-Issue-Key secret → insert D1 (if new) + publish keys-only feed
 *   • GET /api/public           → keys-only feed (safe)
 *   • GET /api/me               → { admin, username, id }
 *
 *  ── Bindings / secrets ──
 *   DB                      D1 database binding (the private license store)
 *   DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET / ADMIN_IDS / SESSION_SECRET
 *   GH_TOKEN / GH_REPO / GH_FILE / GH_BRANCH   (for publishing the keys-only public feed)
 *   ISSUE_SECRET / ALLOW_ORIGIN / CONTACT_WEBHOOK(optional)
 */

const enc = new TextEncoder();
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const b64urlStr = (s) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64url = (s) => decodeURIComponent(escape(atob(s.replace(/-/g,'+').replace(/_/g,'/'))));

async function hmac(secret, msg){
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
}
async function makeSession(env, user){
  const payload = { id:user.id, u:user.username, exp: Date.now()+1000*60*60*8 };
  const body = b64urlStr(JSON.stringify(payload));
  const sig  = await hmac(env.SESSION_SECRET, body);
  return body + '.' + sig;
}
async function readSession(env, cookie){
  if(!cookie) return null;
  const m = /(?:^|;\s*)cdsess=([^;]+)/.exec(cookie); if(!m) return null;
  const [body, sig] = m[1].split('.'); if(!body||!sig) return null;
  if(await hmac(env.SESSION_SECRET, body) !== sig) return null;
  try{ const p = JSON.parse(unb64url(body)); if(p.exp < Date.now()) return null; return p; }catch(e){ return null; }
}
function cors(env){
  return {
    'Access-Control-Allow-Origin': env.ALLOW_ORIGIN || 'https://cracka.dev',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Issue-Key',
  };
}
const json = (env, obj, status=200, extra={}) =>
  new Response(JSON.stringify(obj), {status, headers:{'Content-Type':'application/json', ...cors(env), ...extra}});

function isAdmin(env, sess){
  if(!sess) return false;
  const ids = (env.ADMIN_IDS||'').split(',').map(s=>s.trim()).filter(Boolean);
  return ids.includes(String(sess.id));
}

/* ── D1 helpers ── */
const COLS = ['key','email','first_name','last_name','nickname','signup_date','active','tools','discord_username','discord_id','youtube','twitch','kick','tiktok','notes','last_login','last_updated','last_edit','login_count','is_test_account','referral_source','platform_origin','subscription_tier'];

function rowToRec(row){
  if(!row) return null;
  let tools; try{ tools = JSON.parse(row.tools||'["all"]'); }catch(e){ tools = row.tools ? String(row.tools).split(',').map(s=>s.trim()).filter(Boolean) : ['all']; }
  return {
    key: row.key, email: row.email||'', first_name: row.first_name||'', last_name: row.last_name||'',
    nickname: row.nickname||'', signup_date: row.signup_date||'', active: row.active !== 0,
    tools: (Array.isArray(tools)&&tools.length)?tools:['all'],
    discord_username: row.discord_username||'', discord_id: row.discord_id||'',
    youtube: row.youtube||'', twitch: row.twitch||'', kick: row.kick||'', tiktok: row.tiktok||'',
    notes: row.notes||'', last_login: row.last_login||'', last_updated: row.last_updated||'', last_edit: row.last_edit||'',
    login_count: row.login_count||0, is_test_account: row.is_test_account === 1,
    referral_source: row.referral_source||'', platform_origin: row.platform_origin||'', subscription_tier: row.subscription_tier||''
  };
}
const BLANK = {key:'',email:'',first_name:'',last_name:'',nickname:'',signup_date:'',active:true,tools:['all'],discord_username:'',discord_id:'',youtube:'',twitch:'',kick:'',tiktok:'',notes:'',last_login:'',last_updated:'',last_edit:'',login_count:0,is_test_account:false,referral_source:'',platform_origin:'',subscription_tier:''};

function recToBind(rec){
  const r = {...BLANK, ...rec};
  return [
    r.key, r.email, r.first_name, r.last_name, r.nickname, r.signup_date,
    (r.active === false ? 0 : 1),
    JSON.stringify((Array.isArray(r.tools)&&r.tools.length)?r.tools:['all']),
    r.discord_username, r.discord_id, r.youtube, r.twitch, r.kick, r.tiktok, r.notes,
    r.last_login, r.last_updated, r.last_edit, (r.login_count||0),
    (r.is_test_account ? 1 : 0), r.referral_source, r.platform_origin, r.subscription_tier
  ];
}
async function d1All(env){
  const { results } = await env.DB.prepare(`SELECT * FROM licenses ORDER BY signup_date DESC, key ASC`).all();
  return (results||[]).map(rowToRec);
}
async function d1ByDiscord(env, discordId){
  if(!discordId) return [];
  const { results } = await env.DB.prepare(`SELECT * FROM licenses WHERE discord_id = ?`).bind(String(discordId)).all();
  return (results||[]).map(rowToRec);
}
async function d1ByKey(env, key){
  const row = await env.DB.prepare(`SELECT * FROM licenses WHERE key = ?`).bind(String(key)).first();
  return rowToRec(row);
}
async function d1Upsert(env, rec){
  const placeholders = COLS.map(()=>'?').join(',');
  const updates = COLS.filter(c=>c!=='key').map(c=>`${c}=excluded.${c}`).join(', ');
  const sql = `INSERT INTO licenses (${COLS.join(',')}) VALUES (${placeholders})
               ON CONFLICT(key) DO UPDATE SET ${updates}`;
  await env.DB.prepare(sql).bind(...recToBind(rec)).run();
}

/* ── Public keys-only feed → GitHub (tools + bots read this) ── */
function publicFeed(list){
  return list.map(x => ({ key:x.key, active: x.active !== false, tools: (x.tools&&x.tools.length)?x.tools:['all'] }));
}
async function ghGet(env){
  const url = `https://api.github.com/repos/${env.GH_REPO}/contents/${env.GH_FILE}?ref=${env.GH_BRANCH||'main'}`;
  const r = await fetch(url, {headers:{'Authorization':`Bearer ${env.GH_TOKEN}`,'Accept':'application/vnd.github+json','User-Agent':'cracka-dash'}});
  if(!r.ok) throw new Error('gh get '+r.status);
  const j = await r.json();
  return { sha: j.sha };
}
async function publishKeysOnly(env){
  if(!env.GH_TOKEN || !env.GH_REPO || !env.GH_FILE) return;
  const list = await d1All(env);
  const content = btoa(unescape(encodeURIComponent(JSON.stringify(publicFeed(list), null, 2))));
  const url = `https://api.github.com/repos/${env.GH_REPO}/contents/${env.GH_FILE}`;
  const H = {'Authorization':`Bearer ${env.GH_TOKEN}`,'Accept':'application/vnd.github+json','User-Agent':'cracka-dash','Content-Type':'application/json'};
  async function attempt(){
    let sha; try{ sha = (await ghGet(env)).sha; }catch(e){ sha = undefined; }
    const body = {message:'sync public license keys', content, branch: env.GH_BRANCH||'main'};
    if(sha) body.sha = sha;
    return fetch(url,{method:'PUT',headers:H,body:JSON.stringify(body)});
  }
  let r = await attempt();
  if(r.status === 409) r = await attempt();
  return r.ok;
}

/* ── Off-Cloudflare backup: full D1 records → PRIVATE repo (dated, keep N) ── */
async function doBackup(env){
  if(!env.BACKUP_REPO) return {ok:false, error:'BACKUP_REPO not set'};
  const token = env.BACKUP_TOKEN || env.GH_TOKEN;
  const branch = env.BACKUP_BRANCH || 'main';
  const list = await d1All(env);
  const stamp = new Date().toISOString().slice(0,10);
  const path = `customers/Cracka_Customers_${stamp}.json`;
  const payload = { generatedAt: new Date().toISOString(), count: list.length, records: list };
  const content = btoa(unescape(encodeURIComponent(JSON.stringify(payload, null, 2))));
  const H = {'Authorization':`Bearer ${token}`,'Accept':'application/vnd.github+json','User-Agent':'cracka-dash','Content-Type':'application/json'};
  const fileUrl = `https://api.github.com/repos/${env.BACKUP_REPO}/contents/${path}`;
  let sha; try{ const g = await fetch(fileUrl+`?ref=${branch}`,{headers:H}); if(g.ok){ sha=(await g.json()).sha; } }catch(e){}
  const body = {message:`customer DB backup ${stamp} (${list.length} records)`, content, branch};
  if(sha) body.sha = sha;
  const r = await fetch(fileUrl,{method:'PUT',headers:H,body:JSON.stringify(body)});
  if(!r.ok) return {ok:false, status:r.status, error:(await r.text()).slice(0,200)};
  // prune: keep the newest N dated files (best-effort)
  try{
    const keep = parseInt(env.BACKUP_KEEP||'30',10);
    const lr = await fetch(`https://api.github.com/repos/${env.BACKUP_REPO}/contents/customers?ref=${branch}`,{headers:H});
    if(lr.ok){
      const files = (await lr.json()).filter(f=>/^Cracka_Customers_.*\.json$/.test(f.name)).sort((a,b)=>a.name<b.name?1:-1);
      for(const f of files.slice(keep)){
        await fetch(`https://api.github.com/repos/${env.BACKUP_REPO}/contents/${f.path}`,{method:'DELETE',headers:H,
          body:JSON.stringify({message:`prune old backup ${f.name}`, sha:f.sha, branch})});
      }
    }
  }catch(e){}
  return {ok:true, path, count:list.length};
}

export default {
  async scheduled(event, env, ctx){
    ctx.waitUntil(doBackup(env));
  },
  async fetch(request, env){
    const url = new URL(request.url);
    const p = url.pathname;
    if(request.method === 'OPTIONS') return new Response(null,{headers:cors(env)});

    /* ── Discord OAuth ── */
    if(p === '/auth/discord/start'){
      const redirect = url.searchParams.get('redirect') || (env.ALLOW_ORIGIN||'https://cracka.dev')+'/license.html';
      const state = b64urlStr(JSON.stringify({r:redirect, n:crypto.randomUUID()}));
      const auth = new URL('https://discord.com/api/oauth2/authorize');
      auth.searchParams.set('client_id', env.DISCORD_CLIENT_ID);
      auth.searchParams.set('redirect_uri', url.origin+'/auth/discord/callback');
      auth.searchParams.set('response_type','code');
      auth.searchParams.set('scope','identify');
      auth.searchParams.set('state', state);
      return Response.redirect(auth.toString(), 302);
    }
    if(p === '/auth/discord/callback'){
      const code = url.searchParams.get('code');
      let redirect = (env.ALLOW_ORIGIN||'https://cracka.dev')+'/license.html';
      try{ redirect = JSON.parse(unb64url(url.searchParams.get('state'))).r || redirect; }catch(e){}
      if(!code) return Response.redirect(redirect, 302);
      const tok = await fetch('https://discord.com/api/oauth2/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:new URLSearchParams({client_id:env.DISCORD_CLIENT_ID,client_secret:env.DISCORD_CLIENT_SECRET,grant_type:'authorization_code',code,redirect_uri:url.origin+'/auth/discord/callback'})}).then(r=>r.json());
      if(!tok.access_token) return Response.redirect(redirect, 302);
      const me = await fetch('https://discord.com/api/users/@me',{headers:{'Authorization':'Bearer '+tok.access_token}}).then(r=>r.json());
      // Best-effort: stamp last_login / login_count on the customer's own record (if one matches this Discord id)
      try{
        const now = new Date().toISOString();
        await env.DB.prepare(`UPDATE licenses SET last_login=?, login_count=login_count+1, last_updated=? WHERE discord_id=?`)
          .bind(now, now, String(me.id)).run();
      }catch(e){}
      const sess = await makeSession(env, me);
      const secure = 'cdsess='+sess+'; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=28800';
      return new Response(null,{status:302,headers:{'Location':redirect,'Set-Cookie':secure}});
    }
    if(p === '/auth/logout'){
      const redirect = url.searchParams.get('redirect') || (env.ALLOW_ORIGIN||'https://cracka.dev')+'/license.html';
      return new Response(null,{status:302,headers:{'Location':redirect,'Set-Cookie':'cdsess=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0'}});
    }
    if(p === '/api/me'){
      const sess = await readSession(env, request.headers.get('Cookie'));
      if(!sess) return json(env,{admin:false, authed:false},401);
      return json(env,{admin:isAdmin(env,sess), authed:true, username:sess.u, id:sess.id});
    }

    /* ── Licenses ── */
    if(p === '/api/licenses' && request.method === 'GET'){
      const sess = await readSession(env, request.headers.get('Cookie'));
      if(!sess) return json(env,{error:'login required'},403);
      if(isAdmin(env,sess)){
        return json(env, await d1All(env));               // admin → everyone (full)
      }
      return json(env, await d1ByDiscord(env, sess.id));   // customer → only their own record(s)
    }
    if(p === '/api/licenses' && (request.method === 'POST' || request.method === 'PATCH')){
      const sess = await readSession(env, request.headers.get('Cookie'));
      if(!isAdmin(env,sess)) return json(env,{error:'unauthorized'},403);
      const rec = await request.json();
      if(!rec.key) return json(env,{error:'key required'},400);
      const now = new Date().toISOString();
      const existing = await d1ByKey(env, rec.key);
      if(request.method==='POST' && existing) return json(env,{error:'key exists'},409);
      const merged = {...(existing||BLANK), ...rec, last_edit:now, last_updated:now};
      if(!existing && !merged.signup_date) merged.signup_date = now.slice(0,10);
      await d1Upsert(env, merged);
      await publishKeysOnly(env);
      return json(env,{ok:true, key:rec.key});
    }

    /* ── Public keys-only feed (safe; NO PII) ── */
    if(p === '/api/public' && request.method === 'GET'){
      return json(env, publicFeed(await d1All(env)));
    }

    /* ── Machine-to-machine issue (Make.com → after a Fourthwall Suite purchase) ── */
    if(p === '/api/issue' && request.method === 'POST'){
      if(!env.ISSUE_SECRET || request.headers.get('X-Issue-Key') !== env.ISSUE_SECRET)
        return json(env,{error:'unauthorized'},403);
      let rec; try{ rec = await request.json(); }catch(e){ return json(env,{error:'bad json'},400); }
      if(!rec.key || !rec.email) return json(env,{error:'key and email required'},400);
      const existing = await d1ByKey(env, rec.key);
      if(existing) return json(env,{ok:true, existed:true, key:rec.key});
      const now = new Date().toISOString();
      const merged = {...BLANK, ...rec,
        signup_date: rec.signup_date || now.slice(0,10),
        last_updated: now, last_edit: now,
        platform_origin: rec.platform_origin || 'fourthwall',
        referral_source: rec.referral_source || 'fourthwall'};
      await d1Upsert(env, merged);
      await publishKeysOnly(env);
      return json(env,{ok:true, key:rec.key});
    }

    /* ── Manual backup trigger (secret-gated) — same job the daily cron runs ── */
    if(p === '/api/backup-now' && request.method === 'POST'){
      if(!env.ISSUE_SECRET || request.headers.get('X-Issue-Key') !== env.ISSUE_SECRET)
        return json(env,{error:'unauthorized'},403);
      const res = await doBackup(env);
      return json(env, res, res.ok ? 200 : 500);
    }

    if(p === '/api/resend' && request.method === 'POST'){
      const sess = await readSession(env, request.headers.get('Cookie'));
      if(!isAdmin(env,sess)) return json(env,{error:'unauthorized'},403);
      const {key} = await request.json();
      const rec = await d1ByKey(env, key);
      if(!rec) return json(env,{error:'not found'},404);
      if(env.CONTACT_WEBHOOK) await fetch(env.CONTACT_WEBHOOK,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:'resend',license:rec})});
      return json(env,{ok:true});
    }

    /* ── Contact relay (public) ── */
    if(p === '/api/contact' && request.method === 'POST'){
      const body = await request.json();
      if(!body.email || !body.message) return json(env,{error:'missing fields'},400);
      if(env.CONTACT_WEBHOOK) await fetch(env.CONTACT_WEBHOOK,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:'contact', ...body})});
      return json(env,{ok:true});
    }

    return json(env,{error:'not found'},404);
  }
};
