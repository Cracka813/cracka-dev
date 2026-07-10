/*  Cracka.dev — Dashboard API Worker
 *  Serverless backend for the License Admin page.
 *  Handles: Discord OAuth login (admin-gated), license read/write (GitHub + KV mirror),
 *           license email resend, and the Contact-form relay.
 *
 *  ── Bindings / secrets (wrangler.toml [vars] + `wrangler secret put`) ──
 *   DISCORD_CLIENT_ID       Discord app Client ID
 *   DISCORD_CLIENT_SECRET   Discord app Client Secret          (secret)
 *   ADMIN_IDS               comma-separated Discord user IDs allowed in (e.g. "744...,912...")
 *   SESSION_SECRET          any long random string             (secret)  — signs the login cookie
 *   GH_TOKEN                GitHub token w/ contents:write on the license repo (secret)
 *   GH_REPO                 "Cracka813/djcracka-suite"
 *   GH_FILE                 "Cracka_Suite_License.json"
 *   GH_BRANCH               "main"
 *   CONTACT_WEBHOOK         Make.com/Zoho webhook URL for contact + resend relays (secret, optional)
 *   ALLOW_ORIGIN            "https://cracka.dev"
 *   DASH_KV                 KV namespace binding (license fallback cache + nonce store)
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
  const payload = { id:user.id, u:user.username, exp: Date.now()+1000*60*60*8 }; // 8h
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
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}
const json = (env, obj, status=200, extra={}) =>
  new Response(JSON.stringify(obj), {status, headers:{'Content-Type':'application/json', ...cors(env), ...extra}});

function isAdmin(env, sess){
  if(!sess) return false;
  const ids = (env.ADMIN_IDS||'').split(',').map(s=>s.trim()).filter(Boolean);
  return ids.includes(String(sess.id));
}

/* ── GitHub license file helpers ── */
async function ghGet(env){
  const url = `https://api.github.com/repos/${env.GH_REPO}/contents/${env.GH_FILE}?ref=${env.GH_BRANCH||'main'}`;
  const r = await fetch(url, {headers:{'Authorization':`Bearer ${env.GH_TOKEN}`,'Accept':'application/vnd.github+json','User-Agent':'cracka-dash'}});
  if(!r.ok) throw new Error('gh get '+r.status);
  const j = await r.json();
  const content = JSON.parse(decodeURIComponent(escape(atob(j.content.replace(/\n/g,'')))));
  return { list: Array.isArray(content)?content:[], sha: j.sha };
}
async function ghPut(env, list, sha, msg){
  const url = `https://api.github.com/repos/${env.GH_REPO}/contents/${env.GH_FILE}`;
  const content = btoa(unescape(encodeURIComponent(JSON.stringify(list, null, 2))));
  const r = await fetch(url, {method:'PUT', headers:{'Authorization':`Bearer ${env.GH_TOKEN}`,'Accept':'application/vnd.github+json','User-Agent':'cracka-dash','Content-Type':'application/json'},
    body: JSON.stringify({message: msg||'dashboard update', content, sha, branch: env.GH_BRANCH||'main'})});
  if(!r.ok) throw new Error('gh put '+r.status+' '+await r.text());
  return r.json();
}
const BLANK = {key:'',email:'',first_name:'',last_name:'',nickname:'',signup_date:'',active:true,tools:['all'],discord_username:'',discord_id:'',youtube:'',twitch:'',kick:'',tiktok:'',notes:'',last_login:'',last_updated:'',last_edit:'',login_count:0,is_test_account:false,referral_source:'',platform_origin:'',subscription_tier:''};

export default {
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
      if(!sess) return json(env,{admin:false},401);
      return json(env,{admin:isAdmin(env,sess), username:sess.u, id:sess.id});
    }

    /* ── Licenses ── */
    if(p === '/api/licenses' && request.method === 'GET'){
      try{ const {list} = await ghGet(env); await env.DASH_KV?.put('licenses', JSON.stringify(list)); return json(env, list); }
      catch(e){ const cached = await env.DASH_KV?.get('licenses'); return json(env, cached?JSON.parse(cached):[]); }
    }
    if(p === '/api/licenses' && (request.method === 'POST' || request.method === 'PATCH')){
      const sess = await readSession(env, request.headers.get('Cookie'));
      if(!isAdmin(env,sess)) return json(env,{error:'unauthorized'},403);
      const rec = await request.json();
      if(!rec.key) return json(env,{error:'key required'},400);
      const {list, sha} = await ghGet(env);
      const now = new Date().toISOString();
      const i = list.findIndex(x=>x.key===rec.key);
      if(request.method==='POST' && i>=0) return json(env,{error:'key exists'},409);
      if(i>=0){ list[i] = {...list[i], ...rec, last_edit:now, last_updated:now}; }
      else { list.push({...BLANK, ...rec, signup_date: rec.signup_date||now.slice(0,10), last_edit:now}); }
      await ghPut(env, list, sha, (i>=0?'edit ':'issue ')+rec.key+' via dashboard');
      await env.DASH_KV?.put('licenses', JSON.stringify(list));
      return json(env,{ok:true, key:rec.key});
    }
    if(p === '/api/resend' && request.method === 'POST'){
      const sess = await readSession(env, request.headers.get('Cookie'));
      if(!isAdmin(env,sess)) return json(env,{error:'unauthorized'},403);
      const {key} = await request.json();
      const {list} = await ghGet(env);
      const rec = list.find(x=>x.key===key);
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
