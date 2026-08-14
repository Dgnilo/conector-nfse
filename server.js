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
  producao: "https://nfe.prefeitura.sp.gov.br/ws/lotenfe.asmx",
  homologacao: "https://nfeh.prefeitura.sp.gov.br/ws/lotenfe.asmx",
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
          out.wsdl = {
            status: resp.statusCode === 200 && temEnvioRps ? "OK" : "ERRO",
            http_status: resp.statusCode || null,
            content_type: resp.headers["content-type"] || null,
            bytes: texto.length,
            detalhe: temEnvioRps ? "operacao EnvioRPS presente no WSDL" : "EnvioRPS nao encontrado no WSDL",
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

/** Assinatura do RPS exigida pela Prefeitura de SP (SHA1withRSA sobre string posicional). */
function assinaturaRps(p, keyPem) {
  const tomadorDoc = digitos(p.tomador?.cpf || p.tomador?.cnpj);
  const indicador = p.tomador?.cnpj ? "2" : tomadorDoc.length === 11 ? "1" : "3";
  const data = so(p.rps.data_emissao).replace(/\D/g, "").slice(0, 8); // AAAAMMDD
  const texto =
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
    (indicador === "3" ? "".padStart(14, "0") : zeros(tomadorDoc, 14));

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
<RazaoSocialTomador>${xmlEsc(p.tomador?.nome)}</RazaoSocialTomador>
${enderecoTomadorXml(p.tomador)}
${p.tomador?.email ? `<EmailTomador>${xmlEsc(p.tomador.email)}</EmailTomador>` : ""}
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

// ───────────────────────── SOAP ─────────────────────────

function semDeclaracaoXml(xml) {
  // A Prefeitura rejeita (HTTP 500 HTML) quando o MensagemXML carrega o prologo <?xml ...?>.
  return String(xml || "").replace(/^\s*<\?xml[^>]*\?>\s*/i, "");
}

function soapEnvelope(operacao, xmlPedido, versao) {
  const conteudo = `<${operacao} xmlns="http://www.prefeitura.sp.gov.br/nfe"><VersaoSchema>1</VersaoSchema><MensagemXML><![CDATA[${semDeclaracaoXml(xmlPedido)}]]></MensagemXML></${operacao}>`;
  if (versao === 12) {
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

function postarSoap({ url, body, pfxBuffer, senha, headers, endpoint, versao }) {
  const options = {
    method: "POST",
    host: url.hostname,
    servername: url.hostname,
    path: url.pathname,
    port: 443,
    pfx: pfxBuffer,
    passphrase: senha,
    minVersion: "TLSv1.2",
    headers,
  };
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const texto = Buffer.concat(chunks).toString("utf8");
        log("08", `Prefeitura respondeu HTTP ${res.statusCode || 0}`, {
          endpoint,
          soap: versao === 12 ? "1.2" : "1.1",
          content_type: res.headers["content-type"] || null,
          bytes_resposta: texto.length,
        });
        resolve({
          status: res.statusCode || 0,
          body: texto,
          contentType: res.headers["content-type"] || null,
          endpoint,
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
  const url = new URL(ENDPOINTS[ambiente === "producao" ? "producao" : "homologacao"]);
  const endpoint = url.toString();
  const acao = `http://www.prefeitura.sp.gov.br/nfe/${operacao}`;

  const body11 = Buffer.from(soapEnvelope(operacao, xmlPedido, 11), "utf8");
  log("07", "Enviando para Prefeitura", { endpoint, operacao, soap: "1.1", bytes_envio: body11.length });
  let r = await postarSoap({
    url,
    body: body11,
    pfxBuffer,
    senha,
    endpoint,
    versao: 11,
    headers: {
      "Content-Type": "text/xml; charset=utf-8",
      "Content-Length": body11.length,
      // SOAPAction PRECISA vir entre aspas; sem isso o IIS devolve HTTP 500 em HTML.
      SOAPAction: `"${acao}"`,
      Accept: "text/xml, application/soap+xml, */*",
      "User-Agent": "HumanClinicBI-ConectorNFSe/1.0",
      Connection: "close",
    },
  });

  // Fallback: alguns servidores da Prefeitura so aceitam SOAP 1.2 (500 com HTML generico no 1.1).
  const htmlErro = r.status >= 500 && /html/i.test(r.contentType || "");
  if (htmlErro) {
    const body12 = Buffer.from(soapEnvelope(operacao, xmlPedido, 12), "utf8");
    log("07", "Retentando com SOAP 1.2", { endpoint, operacao, soap: "1.2", bytes_envio: body12.length });
    const r12 = await postarSoap({
      url,
      body: body12,
      pfxBuffer,
      senha,
      endpoint,
      versao: 12,
      headers: {
        "Content-Type": `application/soap+xml; charset=utf-8; action="${acao}"`,
        "Content-Length": body12.length,
        Accept: "application/soap+xml, text/xml, */*",
        "User-Agent": "HumanClinicBI-ConectorNFSe/1.0",
        Connection: "close",
      },
    });
    if (r12.status < 500 || !/html/i.test(r12.contentType || "")) r = r12;
  }
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
    const xmlPedido = xmlEnvioRps(p, keyPem);
    log("05", "XML montado", { bytes: xmlPedido.length });

    etapa = "06";
    const xml = assinarXml(xmlPedido, keyPem, certPem);
    log("06", "XML assinado", { bytes: xml.length });

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

function interpretarTeste(xml) {
  const doc = parser.parse(xml || "");
  const flat = JSON.stringify(doc);
  const sucesso = /"Sucesso":"?true/i.test(flat);
  const codigo = /"Codigo":"?([^",}]+)/i.exec(flat)?.[1] || null;
  const mensagem =
    /"Descricao":"([^"]+)"/i.exec(flat)?.[1] || /"Mensagem":"([^"]+)"/i.exec(flat)?.[1] || null;
  const texto = `${codigo || ""} ${mensagem || ""}`.toLowerCase();
  const assinatura = /assinatura/.test(texto) ? "NAO" : sucesso ? "SIM" : "NAO IDENTIFICADO";
  const schema = /schema|xml|elemento|inv[aá]lid/.test(texto) ? "NAO" : sucesso ? "SIM" : "NAO IDENTIFICADO";
  return { sucesso, codigo, mensagem, assinatura, schema, retorno: doc };
}

app.post("/nfse/testar-xml", async (req, res) => {
  let etapa = "03";
  const p = req.body || {};
  const ambiente = p.ambiente === "producao" ? "producao" : "homologacao";
  const endpoint = ENDPOINTS[ambiente];
  logT("01", "Requisicao recebida", { ambiente, endpoint });
  logT("02", "Token validado");

  // Trava explicita: esta rota so pode falar com a operacao oficial de TESTE.
  if (OPERACOES_PROIBIDAS_NO_TESTE.includes(OPERACAO_TESTE)) {
    logErro("TESTE", "Operacao de emissao bloqueada na rota de teste");
    return res.status(400).json({ erro: "Teste cancelado: operacao de emissao detectada." });
  }

  try {
    const { keyPem, certPem, pfxBuffer } = lerCertificado(
      p.certificado?.pfx_base64,
      p.certificado?.senha,
    );
    logT("03", "PFX aberto", { chave_privada: Boolean(keyPem), certificado: Boolean(certPem) });

    etapa = "04";
    const pedido = xmlTesteEnvioLoteRps(p, keyPem);
    logT("04", "XML de teste montado", { bytes: pedido.length, operacao: OPERACAO_TESTE });

    etapa = "05";
    const xml = assinarXml(pedido, keyPem, certPem);
    const validacao = {
      uri_referencia_vazia: /URI=""/.test(xml),
      id_na_raiz: /<PedidoEnvioLoteRPS[^>]*\sId=/i.test(xml),
      assinatura_ultimo_filho: /<\/(\w+:)?Signature>\s*<\/PedidoEnvioLoteRPS>/i.test(xml),
      endereco_tomador: /<EnderecoTomador>/.test(xml) ? "presente" : "omitido",
    };
    logT("05", "XML assinado", { bytes: xml.length, ...validacao });

    etapa = "06";
    logT("06", "Iniciando mTLS", { endpoint });

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
    logT("09", "Resultado interpretado", {
      sucesso: info.sucesso,
      codigo: info.codigo,
      mensagem: info.mensagem,
    });

    res.json({
      mtls: r.status > 0 ? "OK" : "ERRO",
      soap: r.status === 200 ? "OK" : "ERRO",
      http_status: r.status,
      content_type: r.contentType,
      xml_aceito: info.sucesso ? "SIM" : "NAO",
      assinatura_aceita: info.assinatura,
      schema_aceito: info.schema,
      codigo_prefeitura: info.codigo,
      mensagem_prefeitura: info.mensagem,
      endpoint: r.endpoint,
      operacao: OPERACAO_TESTE,
      versao_schema: "1",
      layout: 1,
      validacao_local: validacao,
      nfse_emitida: false,
      rps_consumido: false,
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
