// Fiscaliza360 no celular: guarda uma cópia do app e dos dados (já cifrados) para abrir sempre, mesmo sem internet
// e mesmo nos segundos em que o GitHub está republicando o site (quando ele responde "404 - não há site aqui").
// Regra: tenta a internet; se a resposta não for boa (erro, 404, 5xx), usa a última cópia boa guardada.
const CACHE = "f360-v2";
self.addEventListener("install", e => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(
  caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));

const chave = req => {   // a página principal vale para qualquer endereço do app (./, ./index.html, ./#alertas...)
  const u = new URL(req.url);
  if (req.mode === "navigate" || u.pathname.endsWith("/") || u.pathname.endsWith("/index.html")) return new Request(new URL("./", self.registration.scope).href);
  u.search = u.pathname.endsWith(".bin") || u.pathname.endsWith(".js") || u.pathname.endsWith(".json") ? "" : u.search;
  return new Request(u.href);
};

self.addEventListener("fetch", e => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin) return;
  if (u.pathname.endsWith("/endereco.bin") || u.pathname.endsWith("/versao.json")) return;   // sempre da internet
  const k = chave(e.request);
  e.respondWith((async () => {
    const guardada = () => caches.match(k);
    try {
      // abrir a página (navigate) não aceita opções extras: pede de novo pelo endereço
      const r = await fetch(e.request.mode === "navigate" ? new Request(e.request.url, {cache: "no-cache", credentials: "same-origin"}) : e.request);
      if (r.ok) {
        const c = r.clone(); caches.open(CACHE).then(x => x.put(k, c));
        return r;
      }
      return (await guardada()) || r;                // 404/5xx do GitHub: usa a cópia boa
    } catch (_) {
      return (await guardada()) || new Response("sem internet", {status: 503});
    }
  })());
});
