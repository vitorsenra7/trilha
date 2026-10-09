// API da Trilha de Vídeos: login, sessão assinada, acessos e dados (Netlify Blobs).
import crypto from 'node:crypto';
import { getStore } from '@netlify/blobs';

export const config = { path: '/api/*' };

const COLLECTIONS = new Set(['trilha', 'progresso', 'notas']);
const ID_RE = /^[A-Za-z0-9_-]{1,100}$/;
const COOKIE = 'tv_session';
const SESSION_SECONDS = 12 * 60 * 60;
const MAX_FAILS = 5;
const LOCK_SECONDS = 15 * 60;
const MAX_BODY = 250 * 1024;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });
const b64u = (buf) => Buffer.from(buf).toString('base64url');

function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 32) throw new Error('SESSION_SECRET ausente ou curta (mínimo 32 caracteres).');
  return s;
}
function envUsers() {
  try {
    const u = JSON.parse(process.env.AUTH_USERS || '{}');
    return u && typeof u === 'object' ? u : {};
  } catch {
    return {};
  }
}

// ---------- senha ----------
function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iter = parseInt(parts[1], 10);
  const salt = Buffer.from(parts[2], 'base64url');
  const expected = Buffer.from(parts[3], 'base64url');
  if (!iter || iter > 2_000_000 || !salt.length || !expected.length) return false;
  const got = crypto.pbkdf2Sync(String(password), salt, iter, expected.length, 'sha256');
  return got.length === expected.length && crypto.timingSafeEqual(got, expected);
}
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const h = crypto.pbkdf2Sync(String(password), salt, 210000, 32, 'sha256');
  return 'pbkdf2$210000$' + b64u(salt) + '$' + b64u(h);
}
const DUMMY = 'pbkdf2$210000$' + b64u(Buffer.alloc(16)) + '$' + b64u(Buffer.alloc(32));

// ---------- armazenamento ----------
function store() {
  if (globalThis.__TEST_STORE) return globalThis.__TEST_STORE;
  return getStore({ name: 'trilha-videos', consistency: 'strong' });
}
function authStore() {
  if (globalThis.__TEST_AUTH_STORE) return globalThis.__TEST_AUTH_STORE;
  return getStore({ name: 'trilha-videos-auth', consistency: 'strong' });
}

// ---------- usuários e sessão ----------
const userKey = (name) => 'user/' + b64u(name);
async function findUser(name) {
  const env = envUsers();
  if (Object.prototype.hasOwnProperty.call(env, name))
    return { usuario: name, hash: env[name], papel: 'admin', fixo: true, nome: name, chave: b64u(name) };
  const rec = await authStore().get(userKey(name), { type: 'json' });
  return rec
    ? { usuario: name, hash: rec.hash, papel: rec.papel === 'admin' ? 'admin' : 'func', fixo: false, nome: rec.nome || name, chave: b64u(name) }
    : null;
}
function signSession(user) {
  const payload = b64u(JSON.stringify({ u: user, exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS }));
  return payload + '.' + b64u(crypto.createHmac('sha256', secret()).update(payload).digest());
}
async function readSession(req) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)'));
  if (!m) return null;
  const [payload, sig] = m[1].split('.');
  if (!payload || !sig) return null;
  const good = crypto.createHmac('sha256', secret()).update(payload).digest();
  const given = Buffer.from(sig, 'base64url');
  if (good.length !== given.length || !crypto.timingSafeEqual(good, given)) return null;
  try {
    const p = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!p.exp || p.exp < Date.now() / 1000) return null;
    return await findUser(String(p.u));
  } catch {
    return null;
  }
}
const cookieHeader = (value, maxAge) => `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const meJson = (u) => ({ usuario: u.usuario, papel: u.papel, nome: u.nome, chave: u.chave, trocaSenha: !u.fixo });

// ---------- bloqueio por tentativas ----------
const ipKey = (ip) => crypto.createHash('sha256').update(String(ip || 'desconhecido')).digest('hex').slice(0, 32);
async function checkLock(key) {
  const rec = await authStore().get(key, { type: 'json' });
  return rec && rec.until && rec.until > Date.now() ? Math.ceil((rec.until - Date.now()) / 1000) : 0;
}
async function registerFail(key) {
  const st = authStore();
  const rec = (await st.get(key, { type: 'json' })) || { count: 0 };
  const count = (rec.until && rec.until <= Date.now() ? 0 : rec.count) + 1;
  await st.setJSON(key, count >= MAX_FAILS ? { count: 0, until: Date.now() + LOCK_SECONDS * 1000 } : { count });
}

async function readJson(req) {
  const text = await req.text();
  if (text.length > MAX_BODY) throw Object.assign(new Error('Corpo grande demais'), { status: 413 });
  try {
    return JSON.parse(text || '{}');
  } catch {
    throw Object.assign(new Error('JSON inválido'), { status: 400 });
  }
}

// ---------- permissões ----------
// trilha: todos leem, só admin altera. progresso: cada um o seu (admin lê todos). notas: só o dono.
function podeLer(u, col, id) {
  if (col === 'trilha') return true;
  if (col === 'progresso') return u.papel === 'admin' || id === u.chave;
  return id === u.chave;
}
function podeEscrever(u, col, id) {
  if (col === 'trilha') return u.papel === 'admin';
  return id === u.chave;
}
const cut = (s, n) => String(s || '').slice(0, n);
const rid = () => crypto.randomBytes(6).toString('hex');

export default async function handler(req, context) {
  try {
    const url = new URL(req.url);
    const seg = url.pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '').split('/').filter(Boolean).map(decodeURIComponent);
    const method = req.method.toUpperCase();

    if (method !== 'GET' && method !== 'HEAD') {
      const origin = req.headers.get('origin');
      if (origin && origin !== url.origin) return json({ erro: 'Origem não permitida.' }, 403);
      if (req.headers.get('x-requested-with') !== 'trilha-videos') return json({ erro: 'Requisição inválida.' }, 400);
    }

    if (seg[0] === 'login' && method === 'POST') {
      const ip = context?.ip || req.headers.get('x-nf-client-connection-ip') || '';
      const key = ipKey(ip);
      const wait = await checkLock(key);
      if (wait) return json({ erro: `Muitas tentativas. Tente de novo em ${Math.ceil(wait / 60)} minuto(s).` }, 429);
      const body = await readJson(req);
      const name = String(body.usuario || '').trim().toLowerCase().slice(0, 60);
      const found = await findUser(name);
      const ok = verifyPassword(String(body.senha || '').slice(0, 200), found ? found.hash : DUMMY) && !!found;
      if (!ok) {
        await registerFail(key);
        return json({ erro: 'Usuário ou senha incorretos.' }, 401);
      }
      await authStore().delete(key);
      return json({ ok: true, ...meJson(found) }, 200, { 'set-cookie': cookieHeader(signSession(name), SESSION_SECONDS) });
    }
    if (seg[0] === 'logout' && method === 'POST') return json({ ok: true }, 200, { 'set-cookie': cookieHeader('', 0) });

    const user = await readSession(req);
    if (!user) return json({ erro: 'Não autenticado.' }, 401);
    const admin = user.papel === 'admin';

    if (seg[0] === 'me' && method === 'GET') return json(meJson(user));

    if (seg[0] === 'senha' && method === 'POST') {
      if (user.fixo) return json({ erro: 'A senha deste usuário é definida no Netlify.' }, 400);
      const b = await readJson(req);
      if (!verifyPassword(String(b.atual || '').slice(0, 200), user.hash)) return json({ erro: 'Senha atual incorreta.' }, 400);
      const nova = String(b.nova || '');
      if (nova.length < 6 || nova.length > 100) return json({ erro: 'A nova senha precisa ter de 6 a 100 caracteres.' }, 400);
      const st = authStore();
      const rec = await st.get(userKey(user.usuario), { type: 'json' });
      await st.setJSON(userKey(user.usuario), { ...rec, hash: hashPassword(nova) });
      return json({ ok: true });
    }

    // ---- acessos (só administrador) ----
    if (seg[0] === 'usuarios') {
      if (!admin) return json({ erro: 'Apenas administradores.' }, 403);
      const st = authStore();
      if (seg.length === 1 && method === 'GET') {
        const { blobs } = await st.list({ prefix: 'user/' });
        const lista = (await Promise.all(blobs.map(async (x) => {
          const r = await st.get(x.key, { type: 'json' });
          return r ? { usuario: r.usuario, papel: r.papel === 'admin' ? 'admin' : 'func', nome: r.nome || r.usuario, chave: b64u(r.usuario), fixo: false } : null;
        }))).filter(Boolean);
        Object.keys(envUsers()).forEach((u) => lista.push({ usuario: u, papel: 'admin', nome: u, chave: b64u(u), fixo: true }));
        lista.sort((a, b) => a.usuario.localeCompare(b.usuario));
        return json({ usuarios: lista });
      }
      if (seg.length === 1 && method === 'POST') {
        const b = await readJson(req);
        const nome = String(b.usuario || '').trim().toLowerCase();
        if (!/^[a-z0-9._ -]{3,40}$/.test(nome)) return json({ erro: 'Usuário: 3 a 40 caracteres (letras sem acento, números, ponto, hífen).' }, 400);
        const senha = String(b.senha || '');
        if (senha.length < 6 || senha.length > 100) return json({ erro: 'A senha precisa ter de 6 a 100 caracteres.' }, 400);
        if (await findUser(nome)) return json({ erro: 'Já existe um usuário com esse nome.' }, 409);
        await st.setJSON(userKey(nome), { usuario: nome, hash: hashPassword(senha), papel: b.papel === 'admin' ? 'admin' : 'func', nome: cut(b.nome, 60) || nome, criado: new Date().toISOString() });
        return json({ ok: true });
      }
      if (seg.length === 2) {
        const nome = String(seg[1]).trim().toLowerCase();
        const u = await findUser(nome);
        if (!u) return json({ erro: 'Usuário não encontrado.' }, 404);
        if (u.fixo) return json({ erro: 'Este administrador é fixo (definido no Netlify).' }, 400);
        if (method === 'PUT') {
          const b = await readJson(req);
          const senha = String(b.senha || '');
          if (senha.length < 6 || senha.length > 100) return json({ erro: 'A senha precisa ter de 6 a 100 caracteres.' }, 400);
          const rec = await st.get(userKey(nome), { type: 'json' });
          await st.setJSON(userKey(nome), { ...rec, hash: hashPassword(senha) });
          return json({ ok: true });
        }
        if (method === 'DELETE') {
          await st.delete(userKey(nome));
          return json({ ok: true });
        }
      }
      return json({ erro: 'Não encontrado.' }, 404);
    }

    // ---- comentários por aula ----
    if (seg[0] === 'coment' && ID_RE.test(seg[1] || '')) {
      const st = store();
      const key = 'comentarios/' + seg[1];
      const doc = (await st.get(key, { type: 'json' })) || { itens: [] };
      if (seg.length === 2 && method === 'GET') return json({ itens: doc.itens });
      const autor = { u: user.usuario, who: user.nome };
      if (seg.length === 2 && method === 'POST') {
        const b = await readJson(req);
        const x = cut(b.x, 1000).trim();
        if (!x) return json({ erro: 'Escreva o comentário.' }, 400);
        const novo = { id: rid(), ...autor, x, em: new Date().toISOString() };
        if (b.parent) {
          const pai = doc.itens.find((c) => c.id === b.parent);
          if (!pai) return json({ erro: 'Comentário não encontrado.' }, 404);
          (pai.re = pai.re || []).push(novo);
        } else doc.itens.unshift({ ...novo, likes: [], re: [] });
        if (doc.itens.length > 500) doc.itens.length = 500;
        await st.setJSON(key, doc);
        return json({ itens: doc.itens });
      }
      if (seg.length === 3 && seg[2] === 'like' && method === 'POST') {
        const b = await readJson(req);
        const c = doc.itens.find((i) => i.id === b.id);
        if (!c) return json({ erro: 'Comentário não encontrado.' }, 404);
        c.likes = c.likes || [];
        const i = c.likes.indexOf(user.usuario);
        if (i >= 0) c.likes.splice(i, 1);
        else c.likes.push(user.usuario);
        await st.setJSON(key, doc);
        return json({ itens: doc.itens });
      }
      if (seg.length === 3 && method === 'DELETE') {
        const id = seg[2];
        const topo = doc.itens.find((c) => c.id === id);
        if (topo) {
          if (topo.u !== user.usuario && !admin) return json({ erro: 'Sem permissão.' }, 403);
          doc.itens = doc.itens.filter((c) => c.id !== id);
        } else {
          for (const c of doc.itens) {
            const r = (c.re || []).find((x) => x.id === id);
            if (r) {
              if (r.u !== user.usuario && !admin) return json({ erro: 'Sem permissão.' }, 403);
              c.re = c.re.filter((x) => x.id !== id);
            }
          }
        }
        await st.setJSON(key, doc);
        return json({ itens: doc.itens });
      }
      return json({ erro: 'Não encontrado.' }, 404);
    }

    // ---- dados genéricos ----
    if (seg[0] === 'col' && seg.length === 2 && method === 'GET') {
      const col = seg[1];
      if (!COLLECTIONS.has(col)) return json({ erro: 'Coleção inválida.' }, 404);
      const st = store();
      const { blobs } = await st.list({ prefix: col + '/' });
      const docs = (await Promise.all(blobs.map(async (b) => {
        const id = b.key.slice(col.length + 1);
        if (!podeLer(user, col, id)) return null;
        const data = await st.get(b.key, { type: 'json' });
        return data == null ? null : { id, data };
      }))).filter(Boolean);
      return json({ docs });
    }
    if (seg[0] === 'doc' && seg.length === 3) {
      const [, col, id] = seg;
      if (!COLLECTIONS.has(col) || !ID_RE.test(id)) return json({ erro: 'Caminho inválido.' }, 400);
      const st = store();
      const key = col + '/' + id;
      if (method === 'GET') {
        if (!podeLer(user, col, id)) return json({ erro: 'Sem permissão.' }, 403);
        const data = await st.get(key, { type: 'json' });
        return data == null ? json({ exists: false }) : json({ exists: true, data });
      }
      if (!podeEscrever(user, col, id)) return json({ erro: 'Sem permissão para alterar.' }, 403);
      if (method === 'PUT') {
        const body = await readJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ erro: 'Documento inválido.' }, 400);
        if (col === 'progresso') {
          body.nome = user.nome;
          body.usuario = user.usuario;
        }
        await st.setJSON(key, body);
        return json({ ok: true });
      }
      if (method === 'DELETE') {
        await st.delete(key);
        return json({ ok: true });
      }
    }
    return json({ erro: 'Não encontrado.' }, 404);
  } catch (e) {
    const status = e && e.status ? e.status : 500;
    if (status === 500) console.error('Erro na API:', e && e.message);
    return json({ erro: status === 500 ? 'Erro interno do servidor.' : e.message }, status);
  }
}
