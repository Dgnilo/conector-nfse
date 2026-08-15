// Conector proprio NFS-e Sao Paulo: mTLS + assinatura XML (RSA-SHA1).
// Recebe chamadas autenticadas do BI e fala com o web service da Prefeitura.
import express from "express";
import https from "node:https";
import tls from "node:tls";
import dns from "node:dns/promises";
import crypto from "node:crypto";
import forge from "node-forge";
import { SignedXml } from "xml-crypto";
import { XMLParser } from "fast-xml-parser";

const PORT = Number(process.env.PORT || 8787);
const TOKEN = process.env.CONECTOR_TOKEN || "";

const ENDPOINTS = {
  // Endpoint atual publicado pela Prefeitura. Ele aceita os layouts 1 e 2.
  // Sao Paulo nao mantem um endpoint separado de homologacao: validacoes sem
  // emissao usam TesteEnvioLoteRPS neste mesmo endereco.
  producao: "https://nfews.prefeitura.sp.gov.br/lotenfe.asmx",
  homologacao: "https://nfews.prefeitura.sp.gov.br/lotenfe.asmx",
};

// ───────────────────── logs de diagnostico (sem segredos) ─────────────────────
// NUNCA logar: senha do certificado, conteudo do PFX, chave privada,
// CONECTOR_TOKEN ou token do emissor.
const ts = () => new Date().toISOString();
const log = (etapa, msg, extra) =>
  console.log(
    `[NFSE-SP] ${etapa} - ${msg}${extra ? " " + JSON.stringify(extra) : ""} @ ${ts()}`,
  );
const logErro = (etapa, msg, extra) =>
  console.error(
    `[NFSE-SP][ERRO][ETAPA ${etapa}] ${msg}${extra ? " " + JSON.stringify(extra) : ""} @ ${ts()}`,
  );
const sanitiza = (texto, max = 2000) =>
  String(texto || "")
    .replace(/<[^>]*(Assinatura|X509Certificate|SignatureValue|DigestValue)[^>]*>[\s\S]*?<\/[^>]*>/gi, "<...omitido...>")
    .replace(/\s+/g, " ")
    .slice(0, max);

const app = express();
app.use(express.json({ limit: "12mb" }));

app.use((req, res, next) => {
  if (req.path === "/health") return next();
  log("01", "Requisicao recebida", { rota: req.path, metodo: req.method });
  const got = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!TOKEN || got !== TOKEN) {
    logErro("02", "Token invalido ou ausente", { rota: req.path });
    return res.status(401).json({ erro: "Token invalido" });
  }
  log("02", "Token validado");
  next();
});


app.get("/health", (_req, res) => res.json({ ok: true }));

// Diagnostico autenticado: apenas confirma o token. Nao emite nada,
// nao gera RPS e nao fala com a Prefeitura.
app.get("/diagnostico", (_req, res) =>
  res.json({ ok: true, autenticado: true, servico: "conector-nfse", versao: 1 }),
);

// Diagnostico de rede/TLS com a Prefeitura. NAO emite NFS-e, NAO consome RPS,
// NAO envia SOAP. Apenas DNS + TLS + leitura do WSDL.
app.get("/diagnostico-prefeitura", async (req, res) => {
  const ambiente = req.query.ambiente === "producao" ? "producao" : "producao";
  const host = new URL(ENDPOINTS[ambiente]).hostname;
  const out = {
    ambiente,
    host,
    dns: { status: "ERRO", detalhe: null },
    render_prefeitura: "ERRO",
    tls: { status: "ERRO", protocolo: null, cifra: null, detalhe: null },
    certificado_remoto: null,
    mtls: { status: "nao testado", detalhe: "Handshake mTLS so ocorre no envio real; nao executado para nao consumir RPS." },
    wsdl: { status: "ERRO", http_status: null, content_type: null, bytes: null, detalhe: null },
    soap: "nao testado",
  };

  try {
    const enderecos = await dns.lookup(host, { all: true });
    out.dns = { status: "OK", detalhe: enderecos.map((e) => e.address) };
  } catch (e) {
    out.dns.detalhe = e?.message || String(e);
    return res.json(out);
  }

  // Handshake TLS simples (sem certificado cliente)
  await new Promise((resolve) => {
    const socket = tls.connect({ host, port: 443, servername: host, timeout: 12000 }, () => {
      const cert = socket.getPeerCertificate(true) || {};
      out.tls = {
        status: "OK",
        protocolo: socket.getProtocol(),
        cifra: socket.getCipher()?.name || null,
        detalhe: socket.authorized ? "cadeia validada" : `nao autorizado: ${socket.authorizationError}`,
      };
      out.render_prefeitura = "OK";
      out.certificado_remoto = {
        subject_cn: cert?.subject?.CN || null,
        emissor_cn: cert?.issuer?.CN || null,
        valido_de: cert?.valid_from || null,
        valido_ate: cert?.valid_to || null,
        cadeia: (() => {
          const nomes = [];
          let c = cert;
          const vistos = new Set();
          while (c && c.fingerprint && !vistos.has(c.fingerprint)) {
            vistos.add(c.fingerprint);
            nomes.push(c?.subject?.CN || "?");
            c = c.issuerCertificate;
          }
          return nomes;
        })(),
      };
      socket.end();
      resolve();
    });
    socket.on("timeout", () => {
      out.tls.detalhe = "timeout no handshake TLS";
      socket.destroy();
      resolve();
    });
    socket.on("error", (e) => {
      out.tls.detalhe = e?.message || String(e);
      resolve();
    });
  });

  if (out.tls.status !== "OK") return res.json(out);

  // WSDL (GET simples, sem SOAP)
  await new Promise((resolve) => {
    const url = new URL(ENDPOINTS[ambiente] + "?wsdl");
    const r = https.request(
      { method: "GET", host: url.hostname, path: url.pathname + url.search, port: 443 },
      (resp) => {
        const chunks = [];
        resp.on("data", (c) => chunks.push(c));
        resp.on("end", () => {
          const texto = Buffer.concat(chunks).toString("utf8");
          const temEnvioRps = /EnvioRPS/.test(texto);
          const st = resp.statusCode || 0;
          out.wsdl = {
            status: st === 200 && temEnvioRps ? "OK" : "ERRO",
            http_status: st || null,
            content_type: resp.headers["content-type"] || null,
            bytes: texto.length,
            detalhe:
              st === 404
                ? "rota/endereco inexistente (nao e problema de certificado)"
                : st === 401 || st === 403
                  ? "autenticacao/autorizacao exigida"
                  : st >= 500
                    ? "erro do servidor da Prefeitura"
                    : temEnvioRps
                      ? "operacao EnvioRPS presente no WSDL"
                      : "EnvioRPS nao encontrado no WSDL",
          };

          resolve();
        });
      },
    );
    r.setTimeout(15000, () => {
      out.wsdl.detalhe = "timeout ao ler o WSDL";
      r.destroy();
      resolve();
    });
    r.on("error", (e) => {
      out.wsdl.detalhe = e?.message || String(e);
      resolve();
    });
    r.end();
  });

  log("DIAG", "Diagnostico Prefeitura concluido", {
    dns: out.dns.status,
    tls: out.tls.status,
    wsdl: out.wsdl.status,
  });
  res.json(out);
});


// ───────────────────────── certificado ─────────────────────────

function lerCertificado(pfxBase64, senha) {
  const p12Der = forge.util.decode64(pfxBase64);
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);

  let keyPem = null;
  let certPem = null;
  const chain = [];

  for (const type of [forge.pki.oids.pkcs8ShroudedKeyBag, forge.pki.oids.keyBag]) {
    const bags = p12.getBags({ bagType: type })[type] || [];
    for (const bag of bags) if (bag.key && !keyPem) keyPem = forge.pki.privateKeyToPem(bag.key);
  }
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  for (const bag of certBags) {
    if (!bag.cert) continue;
    const pem = forge.pki.certificateToPem(bag.cert);
    chain.push(pem);
    const isCA = bag.cert.getExtension("basicConstraints")?.cA;
    if (!isCA && !certPem) certPem = pem;
  }
  if (!certPem) certPem = chain[0];
  if (!keyPem || !certPem) throw new Error("Certificado A1 invalido ou senha incorreta.");

  const der = forge.util.decode64(pfxBase64);
  const pfxBuffer = Buffer.from(der, "binary");
  return { keyPem, certPem, chain, pfxBuffer };
}

// ───────────────────────── helpers de formato ─────────────────────────

const so = (v) => String(v ?? "");
const digitos = (v) => so(v).replace(/\D/g, "");
const zeros = (v, n) => digitos(v).slice(-n).padStart(n, "0");
const esq = (v, n) => so(v).slice(0, n).padEnd(n, " ");
const cent = (v) => Math.round(Number(v || 0) * 100);
const xmlEsc = (v) =>
  so(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

/** String posicional (Layout 1) exigida pela Prefeitura de SP — 86 bytes ASCII. */
function stringAssinaturaRps(p) {
  const tomadorDoc = digitos(p.tomador?.cpf || p.tomador?.cnpj);
  const indicador = p.tomador?.cnpj ? "2" : tomadorDoc.length === 11 ? "1" : "3";
  const data = so(p.rps.data_emissao).replace(/\D/g, "").slice(0, 8); // AAAAMMDD
  return (
    zeros(p.prestador.inscricao_municipal, 8) +
    esq(p.rps.serie || "RPS", 5) +
    zeros(p.rps.numero, 12) +
    data +
    (p.rps.tributacao || "T") +
    (p.rps.status || "N") +
    (p.servico.iss_retido ? "S" : "N") +
    String(cent(p.servico.valor)).padStart(15, "0") +
    String(cent(p.servico.deducoes || 0)).padStart(15, "0") +
    zeros(p.prestador.codigo_servico, 5) +
    indicador +
    (indicador === "3" ? "".padStart(14, "0") : zeros(tomadorDoc, 14))
  );
}

/** Assinatura do RPS exigida pela Prefeitura de SP (SHA1withRSA sobre string posicional). */
function assinaturaRps(p, keyPem) {
  const texto = stringAssinaturaRps(p);
  const bytes = Buffer.from(texto, "ascii").length;
  if (bytes !== 86) throw new Error(`Assinatura municipal com ${bytes} bytes ASCII (esperado 86). Nada foi transmitido.`);
  const signer = crypto.createSign("RSA-SHA1");
  signer.update(Buffer.from(texto, "ascii"));
  return signer.sign(keyPem, "base64");
}


/**
 * EnderecoTomador na sequencia exata do XSD:
 * TipoLogradouro, Logradouro, NumeroEndereco, ComplementoEndereco?, Bairro, Cidade, UF, CEP.
 * Sem todos os campos obrigatorios -> omite o bloco inteiro (nunca endereco parcial).
 */
function enderecoTomadorXml(t) {
  if (!t) return "";
  const tipo = so(t.tipo_logradouro || t.tipoLogradouro).trim();
  const logradouro = so(t.logradouro || t.endereco).trim();
  const numero = so(t.numero || t.numero_endereco).trim();
  const bairro = so(t.bairro).trim();
  const cidade = digitos(t.cidade_ibge || t.codigo_cidade);
  const uf = so(t.uf).trim().toUpperCase();
  const cep = digitos(t.cep);
  if (!tipo || !logradouro || !numero || !bairro || cidade.length !== 7 || uf.length !== 2 || cep.length !== 8) {
    return "";
  }
  const complemento = so(t.complemento).trim();
  return (
    `<EnderecoTomador>` +
    `<TipoLogradouro>${xmlEsc(tipo)}</TipoLogradouro>` +
    `<Logradouro>${xmlEsc(logradouro)}</Logradouro>` +
    `<NumeroEndereco>${xmlEsc(numero)}</NumeroEndereco>` +
    (complemento ? `<ComplementoEndereco>${xmlEsc(complemento)}</ComplementoEndereco>` : "") +
    `<Bairro>${xmlEsc(bairro)}</Bairro>` +
    `<Cidade>${cidade}</Cidade>` +
    `<UF>${uf}</UF>` +
    `<CEP>${cep}</CEP>` +
    `</EnderecoTomador>`
  );
}

/** Bloco <RPS> (namespace vazio) usado tanto no EnvioRPS quanto no TesteEnvioLoteRPS. */
function rpsXml(p, keyPem) {
  const tomadorCpf = digitos(p.tomador?.cpf);
  const tomadorCnpj = digitos(p.tomador?.cnpj);
  const data = so(p.rps.data_emissao).slice(0, 10);
  const aliquota = (Number(p.prestador.aliquota_iss || 0) / 100).toFixed(4);

  const tomadorCpfCnpj = tomadorCnpj
    ? `<CPFCNPJTomador><CNPJ>${tomadorCnpj}</CNPJ></CPFCNPJTomador>`
    : tomadorCpf
      ? `<CPFCNPJTomador><CPF>${tomadorCpf}</CPF></CPFCNPJTomador>`
      : "";

  return `<RPS xmlns="">
<Assinatura>${assinaturaRps(p, keyPem)}</Assinatura>
<ChaveRPS><InscricaoPrestador>${zeros(p.prestador.inscricao_municipal, 8)}</InscricaoPrestador><SerieRPS>${xmlEsc(p.rps.serie || "RPS")}</SerieRPS><NumeroRPS>${digitos(p.rps.numero)}</NumeroRPS></ChaveRPS>
<TipoRPS>RPS</TipoRPS>
<DataEmissao>${data}</DataEmissao>
<StatusRPS>${p.rps.status || "N"}</StatusRPS>
<TributacaoRPS>${p.rps.tributacao || "T"}</TributacaoRPS>
<ValorServicos>${(Number(p.servico.valor || 0)).toFixed(2)}</ValorServicos>
<ValorDeducoes>${(Number(p.servico.deducoes || 0)).toFixed(2)}</ValorDeducoes>
<CodigoServico>${digitos(p.prestador.codigo_servico)}</CodigoServico>
<AliquotaServicos>${aliquota}</AliquotaServicos>
<ISSRetido>${p.servico.iss_retido ? "true" : "false"}</ISSRetido>
${tomadorCpfCnpj}
${so(p.tomador?.nome).trim() ? `<RazaoSocialTomador>${xmlEsc(so(p.tomador.nome).trim())}</RazaoSocialTomador>` : ""}
${enderecoTomadorXml(p.tomador)}
${so(p.tomador?.email).trim() ? `<EmailTomador>${xmlEsc(so(p.tomador.email).trim())}</EmailTomador>` : ""}
<Discriminacao>${xmlEsc(p.servico.discriminacao)}</Discriminacao>
</RPS>`;
}

function xmlEnvioRps(p, keyPem) {
  const cnpjPrestador = zeros(p.prestador.cnpj, 14);
  return `<?xml version="1.0" encoding="UTF-8"?>
<PedidoEnvioRPS xmlns="http://www.prefeitura.sp.gov.br/nfe" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<Cabecalho xmlns="" Versao="1"><CPFCNPJRemetente><CNPJ>${cnpjPrestador}</CNPJ></CPFCNPJRemetente></Cabecalho>
${rpsXml(p, keyPem)}
</PedidoEnvioRPS>`;
}

/** Data corrente no fuso fiscal America/Sao_Paulo (AAAA-MM-DD). Nunca UTC puro. */
function dataHojeSaoPaulo() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Sao_Paulo",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date());
}

/**
 * PedidoEnvioLoteRPS usado APENAS na operacao oficial de TESTE (TesteEnvioLoteRPS).
 * A Prefeitura valida schema, assinatura e regras sem gerar NFS-e.
 */

function xmlTesteEnvioLoteRps(p, keyPem) {
  const cnpjPrestador = zeros(p.prestador.cnpj, 14);
  const data = so(p.rps.data_emissao).slice(0, 10);
  const valor = Number(p.servico.valor || 0).toFixed(2);
  const deducoes = Number(p.servico.deducoes || 0).toFixed(2);
  return `<?xml version="1.0" encoding="UTF-8"?>
<PedidoEnvioLoteRPS xmlns="http://www.prefeitura.sp.gov.br/nfe" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<Cabecalho xmlns="" Versao="1">
<CPFCNPJRemetente><CNPJ>${cnpjPrestador}</CNPJ></CPFCNPJRemetente>
<transacao>true</transacao>
<dtInicio>${data}</dtInicio>
<dtFim>${data}</dtFim>
<QtdRPS>1</QtdRPS>
<ValorTotalServicos>${valor}</ValorTotalServicos>
<ValorTotalDeducoes>${deducoes}</ValorTotalDeducoes>
</Cabecalho>
${rpsXml(p, keyPem)}
</PedidoEnvioLoteRPS>`;
}


function assinarXml(xml, keyPem, certPem) {
  const sig = new SignedXml({
    privateKey: keyPem,
    publicCert: certPem,
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  });
  // Enveloped sobre o documento inteiro: URI="" e SEM atributo Id na raiz.
  sig.addReference({
    xpath: "/*",
    uri: "",
    isEmptyUri: true,
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ],
  });
  // Assinatura como ultimo filho de PedidoEnvioRPS.
  sig.computeSignature(xml, { location: { reference: "/*", action: "append" } });
  const assinado = sig.getSignedXml();

  // Diagnostico seguro: nenhum valor sensivel, apenas hashes e flags.
  const semAssinatura = assinado.replace(/<(\w+:)?Signature[\s\S]*?<\/(\w+:)?Signature>/i, "");
  log("06", "Diagnostico da assinatura", {
    hash_xml_base_sha256: crypto.createHash("sha256").update(xml, "utf8").digest("hex").slice(0, 16),
    hash_xml_assinado_sha256: crypto.createHash("sha256").update(assinado, "utf8").digest("hex").slice(0, 16),
    hash_sem_assinatura_sha256: crypto.createHash("sha256").update(semAssinatura, "utf8").digest("hex").slice(0, 16),
    uri_referencia_vazia: /URI=""/.test(assinado),
    id_na_raiz: /<PedidoEnvioRPS[^>]*\sId=/i.test(assinado),
    assinatura_ultimo_filho: /<\/(\w+:)?Signature>\s*<\/PedidoEnvioRPS>/i.test(assinado),
    bytes: assinado.length,
  });
  return assinado;
}

// ───────────────────── FASE 1: WSDL autenticado (mTLS) ─────────────────────
// Le o WSDL real apresentado ao contribuinte usando o MESMO certificado A1.
// Nao envia SOAP, nao emite NFS-e, nao consome RPS.

let wsdlCache = null; // { obtido_em, endpoint, binding, soapVersao, namespace, acoes }

// URLs candidatas do servico. Somente GET (sem SOAP, sem XML de RPS).
const CANDIDATOS_WSDL = [
  "https://nfews.prefeitura.sp.gov.br/lotenfe.asmx?WSDL",
  "https://nfews.prefeitura.sp.gov.br/lotenfe.asmx",
  "https://nfews.prefeitura.sp.gov.br/ws/lotenfe.asmx?WSDL",
  "https://nfews.prefeitura.sp.gov.br/ws/lotenfe.asmx",
  "https://nfe.prefeitura.sp.gov.br/ws/lotenfe.asmx?WSDL",
  "https://nfe.prefeitura.sp.gov.br/ws/lotenfe.asmx",
];

/** GET seguro (mTLS) em uma URL. Nao envia SOAP nem XML. */
function obterUrl({ href, pfxBuffer, senha }) {
  const url = new URL(href);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        method: "GET",
        host: url.hostname,
        servername: url.hostname,
        path: url.pathname + url.search,
        port: 443,
        pfx: pfxBuffer,
        passphrase: senha,
        minVersion: "TLSv1.2",
        rejectUnauthorized: true,
        headers: { Accept: "text/xml, */*", "User-Agent": "HumanClinicBI-ConectorNFSe/1.0", Connection: "close" },
      },
      (res) => {
        const tlsInfo = infoTls(res.socket);
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode || 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
            tls: tlsInfo,
          }),
        );
      },
    );
    req.setTimeout(20000, () => req.destroy(new Error("timeout ao ler a URL do servico")));
    req.on("error", reject);
    req.end();
  });
}

function classificarHttp(status) {
  if (status === 200) return "conteudo retornado";
  if (status === 401 || status === 403) return "autenticacao/autorizacao";
  if (status === 404) return "rota/endereco inexistente";
  if (status >= 500) return "erro do servidor";
  return `HTTP ${status}`;
}

/** Sonda uma URL seguindo ate 5 redirects, preservando mTLS. */
async function sondarUrl({ href, pfxBuffer, senha }) {
  let atual = href;
  let redirects = 0;
  let ultimoRedirect = null;
  for (;;) {
    let r;
    try {
      r = await obterUrl({ href: atual, pfxBuffer, senha });
    } catch (e) {
      return {
        url: href,
        url_final: atual,
        http_status: null,
        classificacao: "falha de rede/TLS",
        content_type: null,
        bytes: null,
        tls_authorized: "NAO",
        redirect_location: ultimoRedirect,
        primeiro_elemento: null,
        tem_definitions: false,
        tem_wsdl_definitions: false,
        tem_soap_binding: false,
        tem_soap12_binding: false,
        erro: e?.message || String(e),
        body: "",
      };
    }
    const loc = r.headers?.location || null;
    if ([301, 302, 307, 308].includes(r.status) && loc && redirects < 5) {
      redirects += 1;
      ultimoRedirect = new URL(loc, atual).toString();
      atual = ultimoRedirect;
      continue;
    }
    const ct = String(r.headers?.["content-type"] || "") || null;
    const primeiro = /<\s*([A-Za-z_][\w:.-]*)/.exec(r.body.replace(/<\?xml[\s\S]*?\?>/, ""))?.[1] || null;
    return {
      url: href,
      url_final: atual,
      http_status: r.status,
      classificacao: classificarHttp(r.status),
      content_type: ct,
      bytes: Buffer.byteLength(r.body),
      tls_authorized: r.tls.authorized ? "SIM" : "NAO",
      tls: r.tls,
      redirect_location: ultimoRedirect,
      primeiro_elemento: /xml/i.test(ct || "") ? primeiro : null,
      tem_definitions: /<(?:\w+:)?definitions[\s>]/i.test(r.body),
      tem_wsdl_definitions: /<wsdl:definitions[\s>]/i.test(r.body),
      tem_soap_binding: /<soap:binding/i.test(r.body),
      tem_soap12_binding: /<soap12:binding/i.test(r.body),
      erro: null,
      body: r.body,
    };
  }
}

function infoTls(socket) {
  try {
    return {
      protocolo: socket?.getProtocol?.() || null,
      cifra: socket?.getCipher?.()?.name || null,
      authorized: socket?.authorized === true,
      authorizationError: socket?.authorizationError ? String(socket.authorizationError) : null,
    };
  } catch {
    return { protocolo: null, cifra: null, authorized: false, authorizationError: null };
  }
}

/** Extrai endpoint, bindings, versao SOAP e soapAction literal de cada operacao. */
function analisarWsdl(xml) {
  const texto = String(xml || "");
  const targetNs = /targetNamespace="([^"]+)"/.exec(texto)?.[1] || null;
  const bindings = [];
  const re = /<(?:\w+:)?binding\s+name="([^"]+)"\s+type="([^"]+)"[\s\S]*?<\/(?:\w+:)?binding>/g;
  let m;
  while ((m = re.exec(texto))) {
    const bloco = m[0];
    const soap12 = /schemas\.xmlsoap\.org\/wsdl\/soap12\//.test(bloco) || /<soap12:binding/i.test(bloco);
    const acoes = {};
    const reOp = /<(?:\w+:)?operation\s+name="([^"]+)"[\s\S]*?soapAction="([^"]*)"/g;
    let o;
    while ((o = reOp.exec(bloco))) acoes[o[1]] = o[2];
    bindings.push({ nome: m[1], tipo: m[2], soap: soap12 ? "1.2" : "1.1", operacoes: acoes });
  }
  const enderecos = [];
  const reAddr = /<(?:\w+:)?address\s+location="([^"]+)"/g;
  let a;
  while ((a = reAddr.exec(texto))) enderecos.push(a[1]);
  const service = /<(?:\w+:)?service\s+name="([^"]+)"/.exec(texto)?.[1] || null;
  const portas = [];
  const rePorta = /<(?:\w+:)?port\s+name="([^"]+)"\s+binding="([^"]+)"/g;
  let pt;
  while ((pt = rePorta.exec(texto))) portas.push({ nome: pt[1], binding: pt[2] });
  return { targetNs, bindings, enderecos, service, portas };
}

/** Descobre o contrato SOAP real sondando as URLs candidatas (somente GET). */
async function obterContratoWsdl({ ambiente, pfxBuffer, senha, forcar }) {
  if (wsdlCache && !forcar) return wsdlCache;
  const sondagens = [];
  let escolhida = null;
  for (const href of CANDIDATOS_WSDL) {
    const s = await sondarUrl({ href, pfxBuffer, senha });
    const { body, tls, ...publico } = s;
    sondagens.push(publico);
    log("WSDL", "Sondagem de URL do servico", {
      url: publico.url,
      http_status: publico.http_status,
      classificacao: publico.classificacao,
      content_type: publico.content_type,
      bytes: publico.bytes,
      tls_authorized: publico.tls_authorized,
      redirect_location: publico.redirect_location,
      definitions: publico.tem_definitions,
    });
    if (!escolhida && s.http_status === 200 && s.tem_definitions) escolhida = s;
  }
  if (!escolhida) {
    const err = new Error("Nenhuma URL candidata retornou WSDL (HTTP 200 com <definitions>). Nada foi transmitido.");
    err.sondagens = sondagens;
    throw err;
  }
  const info = analisarWsdl(escolhida.body);
  const binding =
    info.bindings.find((b) => b.operacoes.EnvioRPS || b.operacoes.TesteEnvioLoteRPS) || info.bindings[0] || null;
  if (!binding) {
    const err = new Error("WSDL lido, porem nenhum binding SOAP foi encontrado.");
    err.sondagens = sondagens;
    throw err;
  }
  const porta = info.portas.find((p) => String(p.binding).split(":").pop() === binding.nome) || info.portas[0] || null;
  wsdlCache = {
    obtido_em: ts(),
    ambiente,
    url_wsdl: escolhida.url_final,
    http_status: escolhida.http_status,
    tls: escolhida.tls,
    endpoint: info.enderecos[0] || null,
    namespace: info.targetNs,
    service: info.service,
    porta: porta?.nome || null,
    binding: binding.nome,
    soapVersao: binding.soap,
    acoes: binding.operacoes,
    bindings: info.bindings.map((b) => ({ nome: b.nome, soap: b.soap, operacoes: Object.keys(b.operacoes) })),
    bytes: escolhida.bytes,
    sondagens,
  };
  log("WSDL", "Contrato SOAP extraido do WSDL autenticado", {
    url_wsdl: wsdlCache.url_wsdl,
    endpoint: wsdlCache.endpoint,
    binding: wsdlCache.binding,
    soap: wsdlCache.soapVersao,
    operacoes: Object.keys(wsdlCache.acoes).length,
    tls_authorized: wsdlCache.tls?.authorized,
  });
  return wsdlCache;
}

app.post("/nfse/wsdl", async (req, res) => {
  const p = req.body || {};
  const ambiente = p.ambiente === "producao" ? "producao" : "homologacao";
  try {
    const { pfxBuffer } = lerCertificado(p.certificado?.pfx_base64, p.certificado?.senha);
    const c = await obterContratoWsdl({ ambiente, pfxBuffer, senha: p.certificado.senha, forcar: true });
    const pronto =
      !!c.endpoint &&
      !!c.binding &&
      !!c.acoes.EnvioRPS &&
      !!c.acoes.TesteEnvioLoteRPS &&
      c.tls?.authorized === true;
    res.json({
      wsdl_autenticado: "OK",
      url_wsdl: c.url_wsdl,
      http: c.http_status,
      tls_protocolo: c.tls?.protocolo ?? null,
      tls_cifra: c.tls?.cifra ?? null,
      tls_authorized: c.tls?.authorized ? "SIM" : "NAO",
      tls_erro: c.tls?.authorizationError ?? null,
      mtls: c.tls?.authorized ? "OK" : "ERRO",
      certificado_cliente_configurado: "SIM",
      endpoint: c.endpoint,
      namespace: c.namespace,
      service: c.service,
      porta: c.porta,
      soap_binding: c.binding,
      soap_versao: c.soapVersao,
      bindings: c.bindings,
      enviorps_encontrado: c.acoes.EnvioRPS ? "SIM" : "NAO",
      soapaction_enviorps: c.acoes.EnvioRPS ?? null,
      testeenviolote_encontrado: c.acoes.TesteEnvioLoteRPS ? "SIM" : "NAO",
      soapaction_testeenviolote: c.acoes.TesteEnvioLoteRPS ?? null,
      operacoes: Object.keys(c.acoes),
      sondagens: c.sondagens,
      pronto_para_teste: pronto ? "SIM" : "NAO",
      soap_enviado: false,
      nfse_emitida: false,
      rps_consumido: false,
    });
  } catch (e) {
    logErro("WSDL", "Falha ao ler o WSDL autenticado", { erro: e?.message || String(e), code: e?.code || null });
    res.status(502).json({
      wsdl_autenticado: "ERRO",
      http: e?.sondagens?.find((s) => s.http_status)?.http_status ?? null,
      tls_authorized: e?.sondagens?.some((s) => s.tls_authorized === "SIM") ? "SIM" : "NAO",
      sondagens: e?.sondagens ?? [],
      pronto_para_teste: "NAO",
      erro: e?.message || String(e),
      soap_enviado: false,
      nfse_emitida: false,
      rps_consumido: false,
    });
  }
});

// ───────────── FASE 3: validacoes locais obrigatorias (dados + layout XSD) ─────────────

const validoCpf = (v) => {
  const c = digitos(v);
  if (c.length !== 11 || /^(\d)\1{10}$/.test(c)) return false;
  const dv = (n) => {
    let s = 0;
    for (let i = 0; i < n; i++) s += Number(c[i]) * (n + 1 - i);
    const r = (s * 10) % 11 % 10;
    return r === Number(c[n]);
  };
  return dv(9) && dv(10);
};
const validoCnpj = (v) => {
  const c = digitos(v);
  if (c.length !== 14 || /^(\d)\1{13}$/.test(c)) return false;
  const calc = (n) => {
    const pesos = n === 12 ? [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2] : [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let s = 0;
    for (let i = 0; i < n; i++) s += Number(c[i]) * pesos[i];
    const r = s % 11;
    return (r < 2 ? 0 : 11 - r) === Number(c[n]);
  };
  return calc(12) && calc(13);
};

/** Rejeita antes de qualquer transmissao. Nunca corrige por truncamento/preenchimento. */
function validarDados(p) {
  const erros = [];
  const ccm = digitos(p.prestador?.inscricao_municipal);
  if (ccm.length !== 8) erros.push("CCM (Inscricao Municipal) deve ter exatamente 8 digitos.");
  if (!validoCnpj(p.prestador?.cnpj)) erros.push("CNPJ do prestador invalido.");
  const serie = so(p.rps?.serie).trim();
  if (!serie) erros.push("Serie do RPS vazia.");
  if (serie.length > 5) erros.push("Serie do RPS acima do limite oficial (5 caracteres).");
  const numero = digitos(p.rps?.numero);
  if (!numero || Number(numero) <= 0) erros.push("Numero do RPS vazio ou invalido.");
  if (numero.length > 12) erros.push("Numero do RPS acima do limite oficial (12 digitos).");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(so(p.rps?.data_emissao).slice(0, 10)))
    erros.push("Data de emissao fora do formato AAAA-MM-DD.");
  const cs = digitos(p.prestador?.codigo_servico);
  if (!cs || cs.length > 5) erros.push("Codigo de servico em formato invalido.");
  const aliq = Number(p.prestador?.aliquota_iss ?? -1);
  if (!(aliq >= 0 && aliq <= 5)) erros.push("Aliquota de ISS fora da faixa permitida (0% a 5%).");
  const valor = Number(p.servico?.valor);
  if (!(valor > 0)) erros.push("Valor dos servicos invalido.");
  if (Number(p.servico?.deducoes || 0) < 0) erros.push("Valor de deducoes invalido.");
  if (!so(p.servico?.discriminacao).trim()) erros.push("Discriminacao vazia.");
  const cpf = so(p.tomador?.cpf).trim();
  const cnpj = so(p.tomador?.cnpj).trim();
  if (cpf && !validoCpf(cpf)) erros.push("CPF do tomador invalido.");
  if (cnpj && !validoCnpj(cnpj)) erros.push("CNPJ do tomador invalido.");
  return erros;
}

/**
 * Validacao de layout contra PedidoEnvioRPS_v01.xsd / TiposNFe_v01.xsd:
 * confere raiz, namespace, presenca dos elementos obrigatorios e a ordem
 * exigida pela sequence do XSD v1.
 */
const ORDEM_RPS_V1 = [
  "Assinatura",
  "ChaveRPS",
  "TipoRPS",
  "DataEmissao",
  "StatusRPS",
  "TributacaoRPS",
  "ValorServicos",
  "ValorDeducoes",
  "CodigoServico",
  "AliquotaServicos",
  "ISSRetido",
  "CPFCNPJTomador",
  "RazaoSocialTomador",
  "EnderecoTomador",
  "EmailTomador",
  "Discriminacao",
];
const OBRIGATORIOS_RPS_V1 = [
  "Assinatura",
  "ChaveRPS",
  "TipoRPS",
  "DataEmissao",
  "StatusRPS",
  "TributacaoRPS",
  "ValorServicos",
  "ValorDeducoes",
  "CodigoServico",
  "AliquotaServicos",
  "ISSRetido",
  "Discriminacao",
];

function validarLayoutXsd(xml, raizEsperada) {
  const erros = [];
  if (!new RegExp(`<${raizEsperada}[\\s>]`).test(xml)) erros.push(`Raiz ${raizEsperada} ausente.`);
  if (!new RegExp(`<${raizEsperada}[^>]*xmlns="http://www\\.prefeitura\\.sp\\.gov\\.br/nfe"`).test(xml))
    erros.push("Namespace da raiz diferente de http://www.prefeitura.sp.gov.br/nfe.");
  if (!/<Cabecalho[^>]*Versao="1"/.test(xml)) erros.push("Cabecalho sem Versao=\"1\".");
  const rps = /<RPS\b[^>]*>([\s\S]*?)<\/RPS>/.exec(xml)?.[1];
  if (!rps) {
    erros.push("Bloco <RPS> ausente.");
    return erros;
  }
  const presentes = [...rps.matchAll(/<([A-Za-z]+)[\s>/]/g)]
    .map((m) => m[1])
    .filter((n) => ORDEM_RPS_V1.includes(n));
  const unicos = presentes.filter((n, i) => presentes.indexOf(n) === i);
  for (const o of OBRIGATORIOS_RPS_V1) if (!unicos.includes(o)) erros.push(`Elemento obrigatorio ausente: ${o}.`);
  const idx = unicos.map((n) => ORDEM_RPS_V1.indexOf(n));
  for (let i = 1; i < idx.length; i++)
    if (idx[i] < idx[i - 1]) erros.push(`Ordem invalida no XSD v1: ${unicos[i]} apos ${unicos[i - 1]}.`);
  for (const vazio of ["Discriminacao", "CodigoServico", "DataEmissao"])
    if (new RegExp(`<${vazio}></${vazio}>`).test(rps)) erros.push(`Elemento ${vazio} vazio.`);
  return erros;
}

// ───────────── FASE 4: verificacao local das duas assinaturas ─────────────

function conferirAssinaturaMunicipal(p) {
  const texto = stringAssinaturaRps(p);
  const bytes = Buffer.from(texto, "ascii").length;
  return { bytes, ok: bytes === 86 };
}

function verificarXmlDSigLocal(xmlAssinado, certPem) {
  try {
    const sig = new SignedXml({ publicCert: certPem });
    const bloco = /<(\w+:)?Signature[\s\S]*<\/(\w+:)?Signature>/.exec(xmlAssinado)?.[0];
    if (!bloco) return { ok: false, detalhe: "Bloco Signature nao encontrado." };
    sig.loadSignature(bloco);
    const ok = sig.checkSignature(xmlAssinado);
    return { ok, detalhe: ok ? "Assinatura conferida com o certificado do PFX." : (sig.validationErrors || []).join("; ") };
  } catch (e) {
    return { ok: false, detalhe: e?.message || String(e) };
  }
}

// ───────────────────────── SOAP ─────────────────────────

function semDeclaracaoXml(xml) {
  // A Prefeitura rejeita (HTTP 500 HTML) quando o MensagemXML carrega o prologo <?xml ...?>.
  return String(xml || "").replace(/^\s*<\?xml[^>]*\?>\s*/i, "");
}

/** Envelope na versao SOAP declarada pelo binding oficial do WSDL. */
function soapEnvelope(operacao, xmlPedido, soapVersao, namespace) {
  const ns = namespace || "http://www.prefeitura.sp.gov.br/nfe";
  const metodoRequest = `${operacao}Request`;
  const conteudo = `<${metodoRequest} xmlns="${ns}"><VersaoSchema>1</VersaoSchema><MensagemXML><![CDATA[${semDeclaracaoXml(xmlPedido)}]]></MensagemXML></${metodoRequest}>`;
  if (soapVersao === "1.2") {
    return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
<soap12:Body>${conteudo}</soap12:Body>
</soap12:Envelope>`;
  }
  return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>${conteudo}</soap:Body>
</soap:Envelope>`;
}

function postarSoap({ url, body, pfxBuffer, senha, headers, endpoint, soapVersao }) {
  const options = {
    method: "POST",
    host: url.hostname,
    servername: url.hostname,
    path: url.pathname,
    port: 443,
    pfx: pfxBuffer,
    passphrase: senha,
    minVersion: "TLSv1.2",
    rejectUnauthorized: true,
    headers,
  };
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      const tlsInfo = infoTls(res.socket);
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const texto = Buffer.concat(chunks).toString("utf8");
        log("08", `Prefeitura respondeu HTTP ${res.statusCode || 0}`, {
          endpoint,
          soap: soapVersao,
          tls_protocolo: tlsInfo.protocolo,
          tls_cifra: tlsInfo.cifra,
          tls_authorized: tlsInfo.authorized ? "SIM" : "NAO",
          tls_erro: tlsInfo.authorizationError,
          certificado_cliente_configurado: "SIM",
          content_type: res.headers["content-type"] || null,
          bytes_resposta: texto.length,
        });
        resolve({
          status: res.statusCode || 0,
          body: texto,
          contentType: res.headers["content-type"] || null,
          endpoint,
          tls: tlsInfo,
        });
      });
    });
    req.on("error", (e) => {
      logErro("07", "Falha de conexao/TLS com a Prefeitura", {
        endpoint,
        erro: e?.message || String(e),
        code: e?.code || null,
      });
      e.endpoint = endpoint;
      reject(e);
    });
    req.write(body);
    req.end();
  });
}

async function chamarPrefeitura({ ambiente, operacao, xmlPedido, pfxBuffer, senha }) {
  // Endpoint, binding, versao SOAP e SOAPAction vem SEMPRE do WSDL autenticado.
  const contrato = await obterContratoWsdl({ ambiente, pfxBuffer, senha });
  const acao = contrato.acoes[operacao];
  if (!acao) throw new Error(`Operacao ${operacao} nao publicada no WSDL oficial (nada foi enviado).`);

  const url = new URL(contrato.endpoint);
  const endpoint = url.toString();
  const soapVersao = contrato.soapVersao;
  const body = Buffer.from(soapEnvelope(operacao, xmlPedido, soapVersao, contrato.namespace), "utf8");
  const headers =
    soapVersao === "1.2"
      ? {
          "Content-Type": `application/soap+xml; charset=utf-8; action="${acao}"`,
          "Content-Length": body.length,
          Accept: "application/soap+xml, text/xml, */*",
          "User-Agent": "HumanClinicBI-ConectorNFSe/1.0",
          Connection: "close",
        }
      : {
          "Content-Type": "text/xml; charset=utf-8",
          "Content-Length": body.length,
          SOAPAction: `"${acao}"`,
          Accept: "text/xml, */*",
          "User-Agent": "HumanClinicBI-ConectorNFSe/1.0",
          Connection: "close",
        };

  log("07", "Enviando para Prefeitura", {
    endpoint,
    operacao,
    soap: soapVersao,
    soap_binding: contrato.binding,
    soap_action: acao,
    bytes_envio: body.length,
  });

  const r = await postarSoap({ url, body, pfxBuffer, senha, endpoint, soapVersao, headers });
  r.contrato = { endpoint, binding: contrato.binding, soap: soapVersao, acao };
  return r;
}




const parser = new XMLParser({ ignoreAttributes: false, removeNSPrefix: true, parseTagValue: false });

function interpretarRetorno(xml) {
  const doc = parser.parse(xml || "");
  const flat = JSON.stringify(doc);
  const retorno = doc?.Envelope?.Body ?? doc;
  const sucesso = /"Sucesso":"?true/i.test(flat);
  const numero = /"NumeroNFe":"?([^",}]+)/i.exec(flat)?.[1] || null;
  const codigo = /"CodigoVerificacao":"?([^",}]+)/i.exec(flat)?.[1] || null;
  const erro =
    /"Descricao":"([^"]+)"/i.exec(flat)?.[1] ||
    /"Mensagem":"([^"]+)"/i.exec(flat)?.[1] ||
    null;
  return { sucesso, numero, codigo, erro, retorno };
}

// ───────────────────────── rotas ─────────────────────────

app.post("/nfse/emitir", async (req, res) => {
  let etapa = "03";
  const p = req.body || {};
  const ambiente = p.ambiente === "producao" ? "producao" : "homologacao";
  const endpointPrevisto = ENDPOINTS[ambiente];
  const contexto = {
    rota: "/nfse/emitir",
    cnpj_prestador: zeros(p.prestador?.cnpj, 14),
    inscricao_municipal: zeros(p.prestador?.inscricao_municipal, 8),
    rps_numero: digitos(p.rps?.numero),
    rps_serie: so(p.rps?.serie || "RPS"),
    ambiente,
    endpoint: endpointPrevisto,
  };
  try {
    log("03", "PFX recebido", {
      ...contexto,
      pfx_bytes_base64: so(p.certificado?.pfx_base64).length,
      senha_informada: Boolean(p.certificado?.senha),
    });

    const { keyPem, certPem, pfxBuffer } = lerCertificado(
      p.certificado?.pfx_base64,
      p.certificado?.senha,
    );
    log("04", "PFX aberto com sucesso", { chave_privada: Boolean(keyPem), certificado: Boolean(certPem) });

    etapa = "05";
    // FASE 3 — nada e transmitido sem validacao local de dados e de layout XSD.
    const errosDados = validarDados(p);
    if (errosDados.length) {
      logErro("05", "Dados rejeitados localmente (nada transmitido)", { ...contexto, erros: errosDados.length });
      return res.status(422).json({ etapa: "05 - validacao de dados", transmitido: false, erros_dados: errosDados });
    }
    const xmlPedido = xmlEnvioRps(p, keyPem);
    const errosXsd = validarLayoutXsd(xmlPedido, "PedidoEnvioRPS");
    log("05", "XML montado", {
      bytes: xmlPedido.length,
      namespace_raiz: /<PedidoEnvioRPS\s[^>]*xmlns="http:\/\/www\.prefeitura\.sp\.gov\.br\/nfe"/.test(xmlPedido),
      namespace_zerado_em_filhos: /<(Cabecalho|RPS)\b[^>]*xmlns=""/.test(xmlPedido),
      erros_xsd: errosXsd.length,
    });
    if (errosXsd.length) {
      return res.status(422).json({ etapa: "05 - validacao XSD local", transmitido: false, xml_valido_xsd: "NAO", erros_xsd: errosXsd });
    }

    etapa = "06";
    const xml = assinarXml(xmlPedido, keyPem, certPem);
    const dsig = verificarXmlDSigLocal(xml, certPem);
    log("06", "XML assinado", { bytes: xml.length, xmldsig_local: dsig.ok ? "SIM" : "NAO" });
    if (!dsig.ok) {
      return res.status(422).json({ etapa: "06 - XMLDSig local", transmitido: false, xmldsig_local: "NAO", detalhe: dsig.detalhe });
    }


    etapa = "07";
    const r = await chamarPrefeitura({
      ambiente,
      operacao: "EnvioRPS",
      xmlPedido: xml,
      pfxBuffer,
      senha: p.certificado.senha,
    });

    etapa = "08";
    const info = interpretarRetorno(r.body);
    if (r.status !== 200 || !info.sucesso) {
      logErro("08", "Prefeitura retornou erro", {
        ...contexto,
        http_status: r.status,
        content_type: r.contentType,
        bytes: r.body.length,
        mensagem: info.erro || null,
        trecho: sanitiza(r.body, 600),
      });
      return res.status(422).json({
        etapa: "08 - resposta da Prefeitura",
        erro: info.erro || `HTTP ${r.status}`,
        http_status: r.status,
        content_type: r.contentType,
        endpoint: r.endpoint,
        ambiente,
        rps_numero: contexto.rps_numero,
        rps_serie: contexto.rps_serie,
        resposta_trecho: sanitiza(r.body, 2000),
        xml_retorno: r.body.slice(0, 4000),
      });
    }
    log("09", "NFS-e emitida", { ...contexto, numero_nfse: info.numero });
    res.json({
      numero_nfse: info.numero,
      codigo_verificacao: info.codigo,
      link: info.numero
        ? `https://nfe.prefeitura.sp.gov.br/contribuinte/notaprint.aspx?inscricao=${zeros(p.prestador.inscricao_municipal, 8)}&nf=${info.numero}&verificacao=${info.codigo || ""}`
        : null,
      xml_retorno: r.body.slice(0, 8000),
    });
  } catch (e) {
    const nomeEtapa =
      { "03": "leitura/abertura do PFX", "05": "montagem do XML", "06": "assinatura do XML", "07": "conexao com a Prefeitura", "08": "interpretacao do retorno" }[etapa] ||
      "desconhecida";
    logErro(etapa, `Falha na etapa ${nomeEtapa}`, {
      ...contexto,
      erro: e?.message || String(e),
      code: e?.code || null,
      stack: sanitiza(e?.stack, 800),
    });
    res.status(500).json({
      etapa: `${etapa} - ${nomeEtapa}`,
      erro: e?.message || String(e),
      code: e?.code || null,
      endpoint: endpointPrevisto,
      ambiente,
      rps_numero: contexto.rps_numero,
      rps_serie: contexto.rps_serie,
    });
  }
});


// ─────────────── TESTE OFICIAL (TesteEnvioLoteRPS) — NAO emite NFS-e ───────────────
// Operacao oficial de validacao da Prefeitura de SP: valida schema, assinatura e
// regras de negocio SEM gerar NFS-e e SEM consumir a numeracao de RPS.
const OPERACAO_TESTE = "TesteEnvioLoteRPS";
const OPERACOES_PROIBIDAS_NO_TESTE = ["EnvioRPS", "EnvioLoteRPS", "CancelamentoNFe"];

const logT = (etapa, msg, extra) =>
  console.log(`[TESTE-NFSE-SP] ${etapa} - ${msg}${extra ? " " + JSON.stringify(extra) : ""} @ ${ts()}`);

// Parser sem remocao de prefixo: precisamos inspecionar o Body por local-name().
const parserBruto = new XMLParser({ ignoreAttributes: false, parseTagValue: false, processEntities: true });

const nomeLocal = (k) => String(k).replace(/^.*:/, "");

function decodificarEntidades(s) {
  return String(s || "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

/** Colhe recursivamente pares Codigo/Descricao de Erro/Alerta do XML municipal. */
function coletarOcorrencias(no, tipo, saida) {
  if (!no || typeof no !== "object") return saida;
  for (const [k, v] of Object.entries(no)) {
    const nome = nomeLocal(k);
    const lista = Array.isArray(v) ? v : [v];
    if (nome === tipo) {
      for (const item of lista) {
        if (item && typeof item === "object") {
          saida.push({
            tipo,
            codigo: item.Codigo != null ? String(item.Codigo) : null,
            mensagem: item.Descricao != null ? String(item.Descricao) : null,
            correcao: item.Correcao != null ? String(item.Correcao) : null,
          });
        } else if (item != null) {
          saida.push({ tipo, codigo: null, mensagem: String(item), correcao: null });
        }
      }
    } else {
      for (const item of lista) coletarOcorrencias(item, tipo, saida);
    }
  }
  return saida;
}

/**
 * Auditoria da resposta SOAP do TesteEnvioLoteRPS.
 * Nao assume nomes: localiza Body por local-name, o filho *Response e dentro dele *Result.
 */
function auditarRespostaSoap(bruto) {
  const texto = String(bruto || "");
  const out = {
    primeiro_elemento: /<\s*([A-Za-z_][\w.:-]*)/.exec(texto)?.[1] || null,
    soap_response_encontrado: "NAO",
    elemento_response: null,
    result_encontrado: "NAO",
    elemento_result: null,
    formato_result: null,
    xml_municipal_encontrado: "NAO",
    raiz_municipal: null,
    sucesso: "INDETERMINADO",
    ocorrencias: [],
    codigo: null,
    mensagem: null,
    correcao: null,
    soap_fault: null,
  };

  let doc;
  try {
    doc = parserBruto.parse(texto);
  } catch (e) {
    out.mensagem = `Resposta nao pode ser parseada como XML: ${e?.message || String(e)}`;
    return out;
  }

  // 1) Envelope → Body por local-name
  const envKey = Object.keys(doc || {}).find((k) => nomeLocal(k) === "Envelope");
  const env = envKey ? doc[envKey] : null;
  const bodyKey = env ? Object.keys(env).find((k) => nomeLocal(k) === "Body") : null;
  const body = bodyKey ? env[bodyKey] : null;
  if (!body || typeof body !== "object") {
    out.mensagem = "soap:Body nao localizado na resposta.";
    return out;
  }

  const faultKey = Object.keys(body).find((k) => nomeLocal(k) === "Fault");
  if (faultKey) {
    const f = body[faultKey] || {};
    out.soap_fault = String(f.faultstring || f.Reason?.Text || "SOAP Fault");
    out.mensagem = out.soap_fault;
    out.sucesso = "NAO";
    return out;
  }

  // 2) filho *Response
  const respKey =
    Object.keys(body).find((k) => /Response$/i.test(nomeLocal(k))) || Object.keys(body)[0] || null;
  if (!respKey) {
    out.mensagem = "Nenhum elemento dentro de soap:Body.";
    return out;
  }
  out.soap_response_encontrado = "SIM";
  out.elemento_response = nomeLocal(respKey);
  const resp = body[respKey];

  // 3) *Result
  if (!resp || typeof resp !== "object") {
    out.mensagem = "Elemento Response sem conteudo.";
    return out;
  }
  const resultKey =
    Object.keys(resp).find((k) => /Result$/i.test(nomeLocal(k))) ||
    Object.keys(resp).find((k) => !k.startsWith("@_")) ||
    null;
  if (!resultKey) {
    out.mensagem = "Elemento Result nao localizado dentro do Response.";
    return out;
  }
  out.result_encontrado = "SIM";
  out.elemento_result = nomeLocal(resultKey);
  const result = resp[resultKey];

  // 4) formato do conteudo do Result
  const trechoResult = new RegExp(
    `<[^>]*${out.elemento_result}[^>]*>([\\s\\S]*?)<\\/[^>]*${out.elemento_result}>`,
    "i",
  ).exec(texto)?.[1];
  let xmlInterno = null;
  if (result && typeof result === "object") {
    out.formato_result = "XML direto";
    const raizKey = Object.keys(result).find((k) => !k.startsWith("@_"));
    out.raiz_municipal = raizKey ? nomeLocal(raizKey) : null;
    out.xml_municipal_encontrado = raizKey ? "SIM" : "NAO";
    coletarOcorrencias(result, "Erro", out.ocorrencias);
    coletarOcorrencias(result, "Alerta", out.ocorrencias);
    const flat = JSON.stringify(result);
    out.sucesso = /"Sucesso":"?true/i.test(flat) ? "SIM" : out.ocorrencias.length ? "NAO" : "INDETERMINADO";
    return finalizarAuditoria(out);
  }
  if (trechoResult && /<!\[CDATA\[/.test(trechoResult)) {
    out.formato_result = "CDATA";
    xmlInterno = /<!\[CDATA\[([\s\S]*?)\]\]>/.exec(trechoResult)?.[1] || null;
  } else if (trechoResult && /&lt;/.test(trechoResult)) {
    out.formato_result = "XML escapado";
    xmlInterno = decodificarEntidades(trechoResult);
  } else if (typeof result === "string" && /<[A-Za-z]/.test(result)) {
    out.formato_result = "XML escapado";
    xmlInterno = result;
  } else {
    out.formato_result = "string";
    out.mensagem = result != null ? String(result).slice(0, 400) : null;
    return finalizarAuditoria(out);
  }

  if (!xmlInterno || !/<[A-Za-z]/.test(xmlInterno)) return finalizarAuditoria(out);

  let municipal;
  try {
    municipal = parser.parse(xmlInterno);
  } catch (e) {
    out.mensagem = `XML municipal nao parseavel: ${e?.message || String(e)}`;
    return finalizarAuditoria(out);
  }
  out.xml_municipal_encontrado = "SIM";
  out.raiz_municipal = Object.keys(municipal || {}).find((k) => !k.startsWith("?")) || null;
  coletarOcorrencias(municipal, "Erro", out.ocorrencias);
  coletarOcorrencias(municipal, "Alerta", out.ocorrencias);
  const flat = JSON.stringify(municipal);
  const temErro = out.ocorrencias.some((o) => o.tipo === "Erro");
  out.sucesso = /"Sucesso":"?true/i.test(flat) && !temErro ? "SIM" : temErro ? "NAO" : "INDETERMINADO";
  return finalizarAuditoria(out);
}

function finalizarAuditoria(out) {
  const principal = out.ocorrencias.find((o) => o.tipo === "Erro") || out.ocorrencias[0] || null;
  if (principal) {
    out.codigo = principal.codigo;
    out.mensagem = principal.mensagem || out.mensagem;
    out.correcao = principal.correcao;
  }
  return out;
}

function interpretarTeste(xml) {
  const a = auditarRespostaSoap(xml);
  const texto = `${a.codigo || ""} ${a.mensagem || ""}`.toLowerCase();
  const sucesso = a.sucesso === "SIM";
  const assinatura = /assinatura|signature|certificad/.test(texto)
    ? "NAO"
    : sucesso
      ? "SIM"
      : a.sucesso === "NAO"
        ? "SIM"
        : "NAO IDENTIFICADO";
  const schema = /schema|xsd|elemento|estrutura|inv[aá]lid|xml/.test(texto)
    ? "NAO"
    : sucesso
      ? "SIM"
      : "NAO IDENTIFICADO";
  return {
    sucesso,
    codigo: a.codigo,
    mensagem: a.mensagem,
    assinatura,
    schema,
    auditoria: a,
  };
}


app.post("/nfse/testar-xml", async (req, res) => {
  let etapa = "03";
  const p = req.body || {};
  const ambiente = p.ambiente === "producao" ? "producao" : "homologacao";
  const endpoint = ENDPOINTS[ambiente];
  logT("01", "Requisicao recebida", { ambiente, endpoint });
  logT("02", "Token validado");

  // Trava explicita: esta rota so pode falar com a operacao oficial de TESTE.
  if (OPERACAO_TESTE !== "TesteEnvioLoteRPS" || OPERACOES_PROIBIDAS_NO_TESTE.includes(OPERACAO_TESTE)) {
    logErro("TESTE", "Operacao de emissao bloqueada na rota de teste");
    return res.status(400).json({ erro: "Teste cancelado: operacao de emissao detectada." });
  }

  try {
    // FASE 3.0 — datas fiscais no fuso America/Sao_Paulo (nunca UTC puro).
    const hojeSP = dataHojeSaoPaulo();
    const dataRps = so(p.rps?.data_emissao).slice(0, 10);
    logT("03", "Datas fiscais avaliadas", {
      data_atual_sp: hojeSP,
      data_emissao_rps: dataRps,
      dt_inicio: dataRps,
      dt_fim: dataRps,
    });
    if (!dataRps || dataRps > hojeSP) {
      return res.status(422).json({
        etapa: "03 - datas fiscais",
        transmitido: false,
        elegivel: "NAO",
        erro: "RPS NÃO ELEGÍVEL PARA TESTE — DATA DE EMISSÃO FUTURA",
        data_atual_sp: hojeSP,
        data_emissao_rps: dataRps || null,
        dt_inicio_lote: dataRps || null,
        dt_fim_lote: dataRps || null,
        nfse_emitida: false,
        rps_consumido: false,
      });
    }

    // FASE 3 — validacao de dados ANTES de qualquer transmissao.
    const errosDados = validarDados(p);
    if (errosDados.length) {
      logT("03", "Dados rejeitados localmente", { erros: errosDados.length });
      return res.status(422).json({
        etapa: "03 - validacao de dados",
        transmitido: false,
        erros_dados: errosDados,
        nfse_emitida: false,
        rps_consumido: false,
      });
    }


    const { keyPem, certPem, pfxBuffer } = lerCertificado(
      p.certificado?.pfx_base64,
      p.certificado?.senha,
    );
    logT("03", "PFX aberto", { chave_privada: Boolean(keyPem), certificado: Boolean(certPem) });

    etapa = "04";
    // FASE 4 — assinatura municipal: 86 bytes ASCII obrigatorios.
    const municipal = conferirAssinaturaMunicipal(p);
    if (!municipal.ok) {
      logT("04", "Assinatura municipal invalida", municipal);
      return res.status(422).json({
        etapa: "04 - assinatura municipal",
        transmitido: false,
        assinatura_municipal: "ERRO",
        assinatura_municipal_bytes: municipal.bytes,
        nfse_emitida: false,
        rps_consumido: false,
      });
    }
    const pedido = xmlTesteEnvioLoteRps(p, keyPem);
    const errosXsd = validarLayoutXsd(pedido, "PedidoEnvioLoteRPS");
    logT("04", "XML de teste montado", {
      bytes: pedido.length,
      operacao: OPERACAO_TESTE,
      assinatura_municipal_bytes: municipal.bytes,
      erros_xsd: errosXsd.length,
    });
    if (errosXsd.length) {
      return res.status(422).json({
        etapa: "04 - validacao XSD local",
        transmitido: false,
        xml_valido_xsd: "NAO",
        erros_xsd: errosXsd,
        assinatura_municipal: "OK",
        nfse_emitida: false,
        rps_consumido: false,
      });
    }

    etapa = "05";
    const xml = assinarXml(pedido, keyPem, certPem);
    const dsig = verificarXmlDSigLocal(xml, certPem);
    const validacao = {
      uri_referencia_vazia: /URI=""/.test(xml),
      id_na_raiz: /<PedidoEnvioLoteRPS[^>]*\sId=/i.test(xml),
      assinatura_ultimo_filho: /<\/(\w+:)?Signature>\s*<\/PedidoEnvioLoteRPS>/i.test(xml),
      endereco_tomador: /<EnderecoTomador>/.test(xml) ? "presente" : "omitido",
      xml_valido_xsd: "SIM",
      assinatura_municipal_bytes: municipal.bytes,
      xmldsig_local: dsig.ok ? "SIM" : "NAO",
    };
    logT("05", "XML assinado", { bytes: xml.length, ...validacao });
    if (!dsig.ok) {
      return res.status(422).json({
        etapa: "05 - XMLDSig local",
        transmitido: false,
        xmldsig_local: "NAO",
        detalhe: dsig.detalhe,
        nfse_emitida: false,
        rps_consumido: false,
      });
    }

    etapa = "06";
    logT("06", "Iniciando mTLS + leitura do WSDL autenticado", { endpoint });

    etapa = "07";
    logT("07", "SOAP enviado para operacao de TESTE", { operacao: OPERACAO_TESTE });
    const r = await chamarPrefeitura({
      ambiente,
      operacao: OPERACAO_TESTE,
      xmlPedido: xml,
      pfxBuffer,
      senha: p.certificado.senha,
    });


    etapa = "08";
    logT("08", `Prefeitura respondeu HTTP ${r.status}`, {
      content_type: r.contentType,
      bytes: r.body.length,
    });

    etapa = "09";
    const info = interpretarTeste(r.body);
    const a = info.auditoria;
    logT("09", "Resposta SOAP auditada", {
      http_status: r.status,
      content_type: r.contentType,
      bytes: Buffer.byteLength(r.body || "", "utf8"),
      primeiro_elemento: a.primeiro_elemento,
      elemento_response: a.elemento_response,
      elemento_result: a.elemento_result,
      formato_result: a.formato_result,
      raiz_municipal: a.raiz_municipal,
      sucesso: a.sucesso,
      ocorrencias: a.ocorrencias.length,
      codigo: a.codigo,
      mensagem: a.mensagem,
    });

    res.json({
      mtls: r.tls?.authorized ? "OK" : "ERRO",
      tls_authorized: r.tls?.authorized ? "SIM" : "NAO",
      tls_protocolo: r.tls?.protocolo ?? null,
      tls_cifra: r.tls?.cifra ?? null,
      certificado_cliente_configurado: "SIM",
      soap: r.status === 200 ? "OK" : "ERRO",
      soap_binding: r.contrato?.binding ?? null,
      soap_versao: r.contrato?.soap ?? null,
      soap_action: r.contrato?.acao ?? null,
      http_status: r.status,
      content_type: r.contentType,
      bytes_resposta: Buffer.byteLength(r.body || "", "utf8"),
      xml_valido_xsd: "SIM",
      assinatura_municipal: "OK",
      assinatura_municipal_bytes: municipal.bytes,
      xmldsig_local: "SIM",
      xml_aceito: a.sucesso === "SIM" ? "SIM" : "NAO",
      assinatura_aceita: info.assinatura,
      schema_aceito: info.schema,
      codigo_prefeitura: info.codigo,
      mensagem_prefeitura: info.mensagem,
      // Auditoria completa da resposta municipal
      resposta_municipal: {
        primeiro_elemento: a.primeiro_elemento,
        soap_response_encontrado: a.soap_response_encontrado,
        elemento_response: a.elemento_response,
        result_encontrado: a.result_encontrado,
        elemento_result: a.elemento_result,
        formato_result: a.formato_result,
        xml_municipal_encontrado: a.xml_municipal_encontrado,
        raiz_municipal: a.raiz_municipal,
        sucesso: a.sucesso,
        soap_fault: a.soap_fault,
        correcao: a.correcao,
        ocorrencias: a.ocorrencias,
      },
      teste_oficial: a.sucesso === "SIM" ? "APROVADO" : "REJEITADO",
      endpoint: r.endpoint,
      operacao: OPERACAO_TESTE,
      versao_schema: "1",
      layout: 1,
      elegivel: "SIM",
      data_atual_sp: hojeSP,
      data_emissao_rps: dataRps,
      dt_inicio_lote: dataRps,
      dt_fim_lote: dataRps,

      validacao_local: validacao,
      transmitido: true,
      nfse_emitida: false,
      rps_consumido: false,
      rps_incrementado: false,
      resposta_trecho: sanitiza(r.body, 2000),
    });


  } catch (e) {
    const nomeEtapa =
      { "03": "abertura do PFX", "04": "montagem do XML", "05": "assinatura do XML", "06": "mTLS", "07": "envio SOAP de teste", "08": "resposta da Prefeitura", "09": "interpretacao" }[etapa] ||
      "desconhecida";
    logErro(etapa, `Falha no teste oficial (${nomeEtapa})`, {
      erro: e?.message || String(e),
      code: e?.code || null,
    });
    res.status(500).json({
      etapa: `${etapa} - ${nomeEtapa}`,
      erro: e?.message || String(e),
      code: e?.code || null,
      endpoint,
      operacao: OPERACAO_TESTE,
      nfse_emitida: false,
      rps_consumido: false,
    });
  }
});


app.post("/nfse/consultar", async (req, res) => {
  try {
    const p = req.body || {};
    const { keyPem, certPem, pfxBuffer } = lerCertificado(p.certificado?.pfx_base64, p.certificado?.senha);
    const pedido = `<?xml version="1.0" encoding="UTF-8"?>
<PedidoConsultaNFe xmlns="http://www.prefeitura.sp.gov.br/nfe">
<Cabecalho xmlns="" Versao="1"><CPFCNPJRemetente><CNPJ>${zeros(p.prestador.cnpj, 14)}</CNPJ></CPFCNPJRemetente></Cabecalho>
<Detalhe xmlns=""><ChaveRPS><InscricaoPrestador>${zeros(p.prestador.inscricao_municipal, 8)}</InscricaoPrestador><SerieRPS>${xmlEsc(p.rps.serie || "RPS")}</SerieRPS><NumeroRPS>${digitos(p.rps.numero)}</NumeroRPS></ChaveRPS></Detalhe>
</PedidoConsultaNFe>`;
    const r = await chamarPrefeitura({
      ambiente: p.ambiente,
      operacao: "ConsultaNFe",
      xmlPedido: assinarXml(pedido, keyPem, certPem),
      pfxBuffer,
      senha: p.certificado.senha,
    });
    res.json({ ...interpretarRetorno(r.body), xml_retorno: r.body.slice(0, 8000) });
  } catch (e) {
    res.status(500).json({ erro: e?.message || String(e) });
  }
});

app.post("/nfse/cancelar", async (req, res) => {
  try {
    const p = req.body || {};
    const { keyPem, certPem, pfxBuffer } = lerCertificado(p.certificado?.pfx_base64, p.certificado?.senha);
    const insc = zeros(p.prestador.inscricao_municipal, 8);
    const numero = digitos(p.numero_nfse);
    const signer = crypto.createSign("RSA-SHA1");
    signer.update(Buffer.from(insc + String(numero).padStart(12, "0"), "ascii"));
    const assinatura = signer.sign(keyPem, "base64");
    const pedido = `<?xml version="1.0" encoding="UTF-8"?>
<PedidoCancelamentoNFe xmlns="http://www.prefeitura.sp.gov.br/nfe">
<Cabecalho xmlns="" Versao="1"><CPFCNPJRemetente><CNPJ>${zeros(p.prestador.cnpj, 14)}</CNPJ></CPFCNPJRemetente><transacao>true</transacao></Cabecalho>
<Detalhe xmlns=""><ChaveNFe><InscricaoPrestador>${insc}</InscricaoPrestador><NumeroNFe>${numero}</NumeroNFe></ChaveNFe><AssinaturaCancelamento>${assinatura}</AssinaturaCancelamento></Detalhe>
</PedidoCancelamentoNFe>`;
    const r = await chamarPrefeitura({
      ambiente: p.ambiente,
      operacao: "CancelamentoNFe",
      xmlPedido: assinarXml(pedido, keyPem, certPem),
      pfxBuffer,
      senha: p.certificado.senha,
    });
    res.json({ ...interpretarRetorno(r.body), xml_retorno: r.body.slice(0, 8000) });
  } catch (e) {
    res.status(500).json({ erro: e?.message || String(e) });
  }
});

app.listen(PORT, () => console.log(`Conector NFS-e SP rodando na porta ${PORT}`));
