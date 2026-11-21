/* Fiscaliza360 no celular.
   - Pede a senha ao abrir; com ela abre os dados publicados pelo PC (cifrados com AES-GCM).
   - Se o PC estiver ligado (com o Fiscaliza360 aberto e internet), conversa com ele direto: tudo funciona como no computador.
   - Sem o PC, usa os dados publicados; o que só existe no PC mostra um aviso para ligar o computador.
*/
(function () {
  "use strict";
  window.F360_CELULAR = true;
  const BASE = location.pathname.replace(/[^/]*$/, "");          // /fiscaliza360/
  const fetch0 = window.fetch.bind(window);
  const S = {chave: null, senha: "", mapa: {}, opcionais: [], gerado: "", pc: "", token: "", pronto: null, cache: {}};
  let liberar;
  S.pronto = new Promise(r => liberar = r);

  // ------------------------------------------------------------------ cripto
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const hex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
  async function derivar(senha, salHex, iter) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(senha), "PBKDF2", false, ["deriveBits"]);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({name: "PBKDF2", hash: "SHA-256", salt: hex(salHex), iterations: iter}, base, 256));
    S.bits = bits;
    return chaveDeBits(bits);
  }
  const chaveDeBits = bits => crypto.subtle.importKey("raw", bits, "AES-GCM", false, ["decrypt"]);
  const hexDe = u8 => [...u8].map(b => b.toString(16).padStart(2, "0")).join("");
  // a sessão vale enquanto o app estiver aberto (sessionStorage some quando o app é fechado): atualizar não pede a senha de novo
  const SESSAO = "f360-sessao";
  function guardarSessao() { try { sessionStorage.setItem(SESSAO, JSON.stringify({k: hexDe(S.bits), s: S.senha, t: S.token, pc: S.pc})); } catch (_) {} }
  function lerSessao() { try { return JSON.parse(sessionStorage.getItem(SESSAO) || "null"); } catch (_) { return null; } }

  // ------------------------------------------------------------------ atualização automática
  const VERSAO = (document.currentScript && (document.currentScript.src.match(/[?&]v=(\d+)/) || [])[1]) || "";
  async function conferirVersao() {
    try {
      const v = await fetch0(BASE + "versao.json?t=" + Date.now(), {cache: "no-store"}).then(r => r.ok ? r.json() : null);
      if (!v || !v.versao || !VERSAO || v.versao === VERSAO) return;
      try { if (sessionStorage.getItem("f360-recarregou") === v.versao) return; sessionStorage.setItem("f360-recarregou", v.versao); } catch (_) {}   // no máximo uma vez por versão
      const a = document.activeElement;   // só espera se a pessoa estiver no meio de um texto (campo com algo escrito)
      const ocupado = () => !document.hidden && a && /INPUT|TEXTAREA/.test(a.tagName) && a.type !== "search" && (a.value || "").length > 0;
      if (ocupado()) return;   // espera a pessoa terminar de digitar
      guardarSessao();
      let t = document.getElementById("f360atualiza");
      if (!t) { t = document.createElement("div"); t.id = "f360atualiza";
        t.style.cssText = "position:fixed;top:10px;left:50%;transform:translateX(-50%);z-index:100001;background:#0f2a4a;color:#fff;padding:8px 16px;border-radius:20px;font:14px system-ui,sans-serif;box-shadow:0 4px 14px rgba(0,0,0,.3)";
        t.textContent = "Atualizando o Fiscaliza360…"; document.body.appendChild(t); }
      setTimeout(() => location.reload(), 800);
    } catch (_) {}
  }
  setInterval(conferirVersao, 60000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) conferirVersao(); });
  async function abrir(buf, gz) {
    const b = new Uint8Array(buf);
    if (b[0] !== 70 || b[1] !== 51) throw new Error("arquivo inválido");
    const claro = await crypto.subtle.decrypt({name: "AES-GCM", iv: b.slice(2, 14)}, S.chave, b.slice(14));
    if (!gz) return new Uint8Array(claro);
    const s = new Blob([claro]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Uint8Array(await new Response(s).arrayBuffer());
  }
  const txt = u8 => new TextDecoder().decode(u8);

  // ------------------------------------------------------------------ dados publicados
  async function arquivo(chave) {
    if (S.cache[chave]) return S.cache[chave];
    const id = S.mapa[chave];
    if (!id) return null;
    const p = fetch0(BASE + "d/" + id + ".bin", {cache: "no-cache"}).then(r => { if (!r.ok) throw new Error(r.status); return r.arrayBuffer(); })
      .then(b => abrir(b, true));
    S.cache[chave] = p;
    p.catch(() => delete S.cache[chave]);
    return p;
  }
  async function json(chave) { const u = await arquivo(chave); return u ? JSON.parse(txt(u)) : null; }
  function norm(path, params) {
    const q = [...params].filter(([k, v]) => v !== "" && v != null && k !== "f360t").sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : (a[1] < b[1] ? -1 : 1));
    return path + (q.length ? "?" + q.map(([k, v]) => k + "=" + v).join("&") : "");
  }

  // ------------------------------------------------------------------ PC (túnel)
  let procurando = null;   // várias consultas falhando juntas fazem uma procura só
  function procurarPC() { return procurando || (procurando = procurarPC1().finally(() => setTimeout(() => procurando = null, 3000))); }
  async function procurarPC1() {
    try {
      const r = await fetch0(BASE + "endereco.bin?t=" + Date.now(), {cache: "no-store"});
      if (!r.ok) return false;
      const e = JSON.parse(txt(await abrir(await r.arrayBuffer(), false)));
      const c = new AbortController(); setTimeout(() => c.abort(), 6000);
      const s = await fetch0(e.url + "/api/status", {signal: c.signal, cache: "no-store"});
      if (!s.ok) return false;
      const t = await fetch0(e.url + "/api/entrar", {method: "POST", headers: {"Content-Type": "application/json", "X-F360-Cliente": "celular"},
                                                    body: JSON.stringify({senha: S.senha})}).then(r => r.json());
      if (!t.ok) return false;
      S.pc = e.url; S.token = t.token;
      if (S.bits) guardarSessao();
      return true;
    } catch (_) { return false; }
  }
  // sem o PC: procura de novo a cada 20 s e sempre que o app volta para a frente
  const reprocurar = () => { if (S.chave && !S.pc) procurarPC().then(ok => { if (ok) { selo(); avisoSome(); } }); };
  setInterval(reprocurar, 20000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) reprocurar(); });
  const avisoSome = () => { const a = document.getElementById("f360aviso"); if (a) a.remove(); };

  // ------------------------------------------------------------------ aviso "ligue o PC"
  function aviso(oque) {
    let a = document.getElementById("f360aviso");
    if (!a) {
      a = document.createElement("div"); a.id = "f360aviso";
      a.style.cssText = "position:fixed;left:12px;right:12px;bottom:84px;z-index:99999;background:#7a2e0e;color:#fff;padding:12px 14px;border-radius:12px;" +
        "box-shadow:0 6px 24px rgba(0,0,0,.35);font:15px/1.4 system-ui,-apple-system,sans-serif";
      document.body.appendChild(a);
    }
    a.innerHTML = `<b>Esta informação está só no seu PC.</b><br>${oque ? oque + " · " : ""}Ligue o computador e abra o Fiscaliza360 (com internet): o celular conecta sozinho em até 1 minuto e tudo funciona 100%. <button style="margin-left:6px;border:0;background:#fff;color:#7a2e0e;border-radius:6px;padding:3px 9px;font-weight:600">ok</button>`;
    a.querySelector("button").onclick = () => a.remove();
    clearTimeout(aviso.t); aviso.t = setTimeout(() => a && a.remove(), 15000);
  }
  function selo() {
    let s = document.getElementById("f360selo");
    if (!s) { s = document.createElement("div"); s.id = "f360selo";
      // acima da barra de abas (não cobre os botões); pode ser arrastado como o "Perguntar à IA"
      s.style.cssText = "position:fixed;left:10px;bottom:calc(132px + env(safe-area-inset-bottom));z-index:9998;font:12px system-ui,sans-serif;padding:5px 10px;border-radius:14px;color:#fff;cursor:pointer;touch-action:none;user-select:none;-webkit-user-select:none;opacity:.92";
      s.onclick = () => { if (s.dataset.arrastou === "1") return; s.textContent = "procurando o PC…"; procurarPC().then(selo); };
      document.body && document.body.appendChild(s);
      if (window.f360Arrastavel) window.f360Arrastavel(s, "f360-pos-selo"); }
    if (S.pc) { s.style.background = "#1f7a3d"; s.textContent = "● PC conectado: tudo disponível"; }
    else { s.style.background = "#5b6676"; s.textContent = "● Sem o PC · dados de " + (S.gerado || "").replace("T", " ").slice(0, 16).split(" ").map((x, i) => i ? x : x.split("-").reverse().join("/")).join(" "); }
  }

  // ------------------------------------------------------------------ troca das consultas
  const resp = (corpo, tipo = "application/json; charset=utf-8", status = 200) => new Response(corpo, {status, headers: {"Content-Type": tipo}});
  const precisaPC = (oque) => { aviso(oque); return resp(JSON.stringify({erro: "Disponível só com o PC ligado.", precisa_pc: true}), undefined, 503); };
  const NOMES = {"/api/busca": "Busca geral", "/api/tabela": "Tabelas completas", "/api/dossie": "Dossiê", "/api/empresa": "Ficha desta empresa",
                 "/api/opcoes": "Filtros das tabelas", "/api/verificar": "Verificar proposição", "/api/ia/chat": "Chat com a IA", "/api/meudoc": "Seus documentos"};

  let falhasPC = 0;
  window.fetch = async function (entrada, opcoes) {
    // o painel chama fetch com texto, com URL ou com Request: os três precisam passar por aqui
    const url = new URL(entrada instanceof URL ? entrada.href : typeof entrada === "string" ? entrada : entrada.url, location.href);
    const meu = url.origin === location.origin && /^\/(api|m)\//.test(url.pathname);
    if (!meu) return fetch0(entrada, opcoes);
    await S.pronto;
    const metodo = ((opcoes && opcoes.method) || (entrada instanceof Request ? entrada.method : "") || "GET").toUpperCase();
    // 1º: o que já veio para o celular abre na hora (o túnel até o PC é lento para arquivos grandes)
    const AO_VIVO = /^\/api\/(status|coletas|meus_municipios|ia\/|celular|atualizar|coleta_bahia)/;
    if (metodo === "GET" && !AO_VIVO.test(url.pathname) && !url.pathname.startsWith("/api/tse/")) {
      let k = norm(url.pathname, url.searchParams);
      if (!S.mapa[k]) k = norm(url.pathname, [...url.searchParams].filter(([n]) => !S.opcionais.includes(n)));
      if (S.mapa[k] && (S.mapa[norm(url.pathname, url.searchParams)] || !S.pc)) {
        try { const u = await arquivo(k); return resp(u, url.pathname.endsWith(".html") ? "text/html; charset=utf-8" : "application/json; charset=utf-8"); } catch (_) {}
      }
    }
    if (S.pc) {   // PC ligado: conversa direto com ele; se falhar, cai nos dados guardados (nunca mostra erro de conexão)
      try {
        const h = new Headers((opcoes && opcoes.headers) || {}); h.set("X-F360-Token", S.token);
        const c = new AbortController(), tm = setTimeout(() => c.abort(), 45000);
        let r = await fetch0(S.pc + url.pathname + url.search, Object.assign({}, opcoes || {}, {headers: h, signal: c.signal}));
        clearTimeout(tm);
        if (r.status === 401 && await procurarPC()) {   // token vencido: entra de novo uma vez
          h.set("X-F360-Token", S.token);
          r = await fetch0(S.pc + url.pathname + url.search, Object.assign({}, opcoes || {}, {headers: h}));
        }
        if (r.ok || metodo !== "GET" || (r.status >= 400 && r.status < 500 && r.status !== 401)) { falhasPC = 0; return r; }
      } catch (_) {}
      // falhou (PC reiniciando, rede oscilando): reconecta na hora e tenta mais uma vez antes de desistir
      if (await procurarPC()) {
        try {
          const h2 = new Headers((opcoes && opcoes.headers) || {}); h2.set("X-F360-Token", S.token);
          const r2 = await fetch0(S.pc + url.pathname + url.search, Object.assign({}, opcoes || {}, {headers: h2}));
          if (r2.ok || metodo !== "GET") { falhasPC = 0; selo(); return r2; }
        } catch (_) {}
      } else { S.pc = ""; selo(); }   // o PC não respondeu mesmo: passa a usar os dados guardados
    }
    if (metodo !== "GET") return precisaPC("Enviar ou alterar dados");
    if (url.pathname.startsWith("/api/tse/")) return tse(url);
    let chave = norm(url.pathname, url.searchParams);
    if (!S.mapa[chave]) {   // tenta sem os parâmetros que só refinam (ex.: município de interesse)
      const p = [...url.searchParams].filter(([k]) => !S.opcionais.includes(k));
      chave = norm(url.pathname, p);
    }
    if (S.mapa[chave]) {
      const u = await arquivo(chave);
      const tipo = url.pathname.endsWith(".html") ? "text/html; charset=utf-8" : "application/json; charset=utf-8";
      return resp(u, tipo);
    }
    if (url.pathname === "/api/ia/status") return resp(JSON.stringify({configurada: false, precisa_pc: true}));
    return precisaPC(NOMES[url.pathname] || "");
  };

  window.F360_abrirPC = (caminho, oque) => {
    if (S.pc) window.open(S.pc + caminho + (caminho.includes("?") ? "&" : "?") + "f360t=" + encodeURIComponent(S.token), "_blank");
    else aviso(oque || "");
  };
  // links e janelas que apontam para o PC (documentos, planilhas, PDFs oficiais)
  document.addEventListener("click", e => {
    const a = e.target.closest && e.target.closest("a[href]");
    if (!a) return;
    const h = a.getAttribute("href");
    if (!/^\/(api|m)\//.test(h)) return;
    e.preventDefault();
    if (S.pc) window.open(S.pc + h + (h.includes("?") ? "&" : "?") + "f360t=" + encodeURIComponent(S.token), "_blank");
    else aviso("Documento");
  }, true);

  // painel do município (iframe): carrega pelo mesmo caminho e faz o iframe usar estas consultas
  new MutationObserver(() => {
    document.querySelectorAll("iframe").forEach(f => {
      const s = f.getAttribute("src") || "";
      if (!s.startsWith("/m/") || f.dataset.f360) return;
      f.dataset.f360 = "1"; f.removeAttribute("src");
      window.fetch(s).then(r => r.ok ? r.text() : Promise.reject(r.status)).then(h => {
        h = h.replace(/(href|src)="\/(lib|icones)\//g, `$1="${BASE}$2/`)
             .replace("<head>", `<head><script>window.F360_CELULAR=true;window.fetch=(...a)=>parent.fetch(...a);</script>`);
        f.srcdoc = h;
      }).catch(() => { f.srcdoc = "<p style='font:16px sans-serif;padding:20px'>Este município ainda não foi enviado para o celular. Ligue o PC para ver.</p>"; });
    });
  }).observe(document.documentElement, {childList: true, subtree: true});

  // ------------------------------------------------------------------ TSE sem o PC (mesmas contas do tse_consulta.py)
  const norm2 = s => (s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toUpperCase().replace(/[^A-Z0-9 ]/g, " ").replace(/\s+/g, " ").trim();
  async function candAno(ano) {
    const k = "tse:cand:" + ano; if (S.cache["obj:" + k]) return S.cache["obj:" + k];
    const j = await json(k); if (!j) return [];
    const L = j.rows.map(r => Object.fromEntries(j.cols.map((c, i) => [c, r[i]])));
    L.forEach(x => { x.nome_n = x.nome_n || norm2(x.nome); x.urna_n = x.urna_n || norm2(x.urna); });
    return (S.cache["obj:" + k] = L);
  }
  async function todosCands() { const anos = (await json("tse:anos")) || []; return (await Promise.all(anos.map(candAno))).flat(); }
  async function tse(url) {
    const q = Object.fromEntries(url.searchParams), p = url.pathname, R = o => resp(JSON.stringify(o));
    if (p === "/api/tse/status") return R(Object.assign((await json(norm("/api/tse/status", []))) || {}, {celular: true}));
    if (p === "/api/tse/opcoes") { const m = (await json("tse:municipios")) || []; return R({municipios: m.map(([cd_mun, nome]) => ({cd_mun, nome})), cargos: []}); }
    if (p === "/api/tse/busca") {
      const termos = norm2(q.q).split(" ").filter(Boolean);
      let L = await todosCands();
      L = L.filter(x => termos.every(t => x.nome_n.includes(t) || (x.urna_n || "").includes(t)) &&
        (!q.esfera || x.esfera === q.esfera) && (!q.ano || String(x.ano) === String(q.ano)) && (!q.cargo || x.cargo.toUpperCase() === q.cargo.toUpperCase()) &&
        (!q.municipio || x.municipio.toUpperCase() === q.municipio.toUpperCase() || x.ue === q.municipio) && (q.eleitos !== "1" || x.eleito));
      if (!termos.length && !q.municipio) return R([]);
      const por = {};
      L.forEach(x => (por[x.pessoa] ||= []).push(x));
      const pessoas = Object.keys(por).sort((a, b) => (Math.max(...por[b].map(x => x.eleito)) - Math.max(...por[a].map(x => x.eleito))) ||
        (Math.max(...por[b].map(x => x.votos)) - Math.max(...por[a].map(x => x.votos)))).slice(0, 80);
      const tudo = await todosCands();
      return R(pessoas.map(pe => { const cs = tudo.filter(x => x.pessoa === pe).sort((a, b) => b.ano - a.ano);
        return {pessoa: pe, nome: cs[0].nome, urna: cs[0].urna, candidaturas: cs}; }));
    }
    if (p === "/api/tse/eleicao") {
      const L = (await candAno(q.ano)).filter(x => x.cargo.toUpperCase() === (q.cargo || "").toUpperCase() &&
        (!q.municipio || x.ue === q.municipio || x.municipio.toUpperCase() === q.municipio.toUpperCase()));
      return R(L.sort((a, b) => (b.eleito - a.eleito) || (b.votos - a.votos)));
    }
    if (p === "/api/tse/candidatura") {
      const ano = q.ano, L = await candAno(ano), k = L.find(x => String(x.sq) === String(q.sq));
      if (!k) return R({erro: "Candidatura não encontrada."});
      const muns = Object.fromEntries(((await json("tse:municipios")) || []).map(([c, n]) => [c, n]));
      const vm = ((await json(`tse:vm:${ano}:${Number(k.sq) % 32}`)) || []).filter(r => String(r[1]) === String(k.sq) && r[0] === 1);
      const tm = {}; ((await json("tse:tm:" + ano)) || []).forEach(([t, cg, cm, n]) => { if (t === 1 && cg === k.cd_cargo) tm[cm] = n; });
      const municipios = vm.map(([, , cm, v]) => ({cd_mun: cm, municipio: muns[cm] || cm, votos: v, nominais: tm[cm] || null,
        pct: tm[cm] ? Math.round(10000 * v / tm[cm]) / 100 : null, pct_do_total: k.votos ? Math.round(10000 * v / k.votos) / 100 : null}))
        .sort((a, b) => b.votos - a.votos);
      const alvo = q.mun || (k.esfera === "municipal" ? k.ue : (municipios[0] || {}).cd_mun);
      let locais = [], bairros = [];
      const D = alvo ? await json(`tse:loc:${ano}:${alvo}`) : null;
      if (D) {
        const val = {}; D.t.forEach(([t, cg, z, l, v]) => { if (t === 1 && cg === k.cd_cargo) val[z + "|" + l] = (val[z + "|" + l] || 0) + v; });
        const inf = {}; D.l.forEach(([z, l, nome, endereco, bairro, lat, lon, eleitores]) => inf[z + "|" + l] = {nome, endereco, bairro, lat, lon, eleitores});
        const ag = {}; D.v.forEach(([t, sq, z, l, v]) => { if (t === 1 && String(sq) === String(k.sq)) ag[z + "|" + l] = (ag[z + "|" + l] || 0) + v; });
        locais = Object.entries(ag).map(([zl, v]) => { const [z, l] = zl.split("|").map(Number); const i = inf[zl] || {};
          return Object.assign({zona: z, local: l, votos: v, validos: val[zl] || null, pct: val[zl] ? Math.round(10000 * v / val[zl]) / 100 : null}, i); })
          .sort((a, b) => b.votos - a.votos);
        const b = {};
        locais.forEach(l => { const n = l.bairro || "Bairro não informado"; const x = (b[n] ||= {bairro: n, votos: 0, validos: 0, locais: 0});
          x.votos += l.votos; x.validos += l.validos || 0; x.locais++; });
        bairros = Object.values(b).sort((a, c) => c.votos - a.votos).map(x => Object.assign(x, {pct: x.validos ? Math.round(10000 * x.votos / x.validos) / 100 : null}));
      }
      const outras = (await todosCands()).filter(x => x.pessoa === k.pessoa).sort((a, b) => b.ano - a.ano);
      const disputa = L.filter(x => x.cd_cargo === k.cd_cargo && x.ue === k.ue && x.votos > 0).sort((a, b) => b.votos - a.votos).slice(0, 60);
      const eleitos = L.filter(x => x.cd_cargo === k.cd_cargo && x.ue === k.ue && x.eleito);
      return R({candidato: k, municipios, municipio_detalhe: {cd_mun: alvo, nome: muns[alvo] || k.municipio}, locais, bairros, outras, disputa,
                n_eleitos: eleitos.length, menor_eleito: eleitos.length ? Math.min(...eleitos.map(x => x.votos)) : null, tem_locais: !!D});
    }
    return precisaPC("");
  }

  // ------------------------------------------------------------------ tela de senha
  function telaSenha() {
    const d = document.createElement("div"); d.id = "f360senha";
    d.style.cssText = "position:fixed;inset:0;z-index:100000;background:#0f2a4a;display:flex;align-items:center;justify-content:center;padding:16px;font:16px/1.45 system-ui,-apple-system,sans-serif";
    d.innerHTML = `<form style="background:#fff;border-radius:14px;padding:26px 22px;width:100%;max-width:360px;box-sizing:border-box">
      <div style="font-size:25px;font-weight:700;color:#0f2a4a">Fiscaliza<span style="color:#EF9F27">360</span></div>
      <p style="color:#5b6676;font-size:14px;margin:6px 0 14px">Digite a mesma senha do programa do computador.</p>
      <input type="text" name="username" value="Fiscaliza360" autocomplete="username" hidden>
      <input type="password" id="f360s" autocomplete="current-password" placeholder="Senha" style="width:100%;box-sizing:border-box;font:inherit;padding:12px;border:1px solid #c9d1dc;border-radius:8px">
      <div id="f360e" style="color:#b42318;font-size:14px;min-height:1.3em;margin-top:8px"></div>
      <button style="width:100%;margin-top:10px;padding:12px;font:inherit;font-weight:600;color:#fff;background:#0f5c8a;border:0;border-radius:8px">Entrar</button>
      <p id="f360i" style="color:#7a8594;font-size:12px;margin:12px 0 0"></p></form>`;
    const por = () => (document.body || document.documentElement).appendChild(d);
    document.body ? por() : document.addEventListener("DOMContentLoaded", por);
    const ir = async ev => {
      ev.preventDefault();
      const e = d.querySelector("#f360e"), b = d.querySelector("button"); e.textContent = ""; b.disabled = true; b.textContent = "Abrindo…";
      try {
        const C = await fetch0(BASE + "chave.json", {cache: "no-store"}).then(r => r.json());
        S.chave = await derivar(d.querySelector("#f360s").value, C.sal, C.iter);
        await abrir(b64(C.teste).buffer, false);
        S.senha = d.querySelector("#f360s").value;
        const I = JSON.parse(txt(await abrir(await fetch0(BASE + "d/indice.bin", {cache: "no-cache"}).then(r => r.arrayBuffer()), true)));
        S.mapa = I.mapa; S.opcionais = [...(I.opcionais || []), 'lembrar']; S.gerado = I.gerado;
        b.textContent = "Procurando o PC…";
        await procurarPC();
        guardarSessao();
        d.remove(); selo(); liberar();
      } catch (er) {
        S.chave = null;
        e.textContent = /OperationError|decrypt/i.test(String(er && (er.name || er))) ? "Senha incorreta." : "Não foi possível abrir: " + (er && er.message || er);
        b.disabled = false; b.textContent = "Entrar";
      }
    };
    d.querySelector("form").addEventListener("submit", ir);
    setTimeout(() => d.querySelector("#f360s").focus(), 300);
  }
  // abre direto se o app já estava aberto (só recarregou para atualizar); senão pede a senha
  (async () => {
    const s = lerSessao();
    if (s && s.k) {
      try {
        S.bits = hex(s.k); S.chave = await chaveDeBits(S.bits); S.senha = s.s || ""; S.token = s.t || ""; S.pc = s.pc || "";
        const I = JSON.parse(txt(await abrir(await fetch0(BASE + "d/indice.bin", {cache: "no-cache"}).then(r => r.arrayBuffer()), true)));
        S.mapa = I.mapa; S.opcionais = [...(I.opcionais || []), 'lembrar']; S.gerado = I.gerado;
        if (S.pc) { try { const r = await fetch0(S.pc + "/api/status", {cache: "no-store"}); if (!r.ok) S.pc = ""; } catch (_) { S.pc = ""; } }
        if (!S.pc) procurarPC().then(ok => { if (ok) { selo(); guardarSessao(); } });
        const pronto = () => { selo(); liberar(); };
        document.body ? pronto() : document.addEventListener("DOMContentLoaded", pronto);
        return;
      } catch (_) { try { sessionStorage.removeItem(SESSAO); } catch (__) {} S.chave = null; }
    }
    telaSenha();
  })();
  if ("serviceWorker" in navigator) navigator.serviceWorker.register(BASE + "sw.js").catch(() => {});
})();
