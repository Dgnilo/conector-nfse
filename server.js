// Conector proprio NFS-e Sao Paulo: mTLS + assinatura XML (RSA-SHA1).
// Recebe chamadas autenticadas do BI e fala com o web service da Prefeitura.
import express from "express";
import https from "node:https";
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

const app = express();
app.use(express.json({ limit: "12mb" }));

app.use((req, res, next) => {
  if (req.path === "/health") return next();
  const got = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!TOKEN || got !== TOKEN) return res.status(401).json({ erro: "Token invalido" });
  next();
});

app.get("/health", (_req, res) => res.json({ ok: true }));

// Diagnostico autenticado: apenas confirma o token. Nao emite nada,
// nao gera RPS e nao fala com a Prefeitura.
app.get("/diagnostico", (_req, res) =>
  res.json({ ok: true, autenticado: true, servico: "conector-nfse", versao: 1 }),
);


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

function xmlEnvioRps(p, keyPem) {
  const tomadorCpf = digitos(p.tomador?.cpf);
  const tomadorCnpj = digitos(p.tomador?.cnpj);
  const data = so(p.rps.data_emissao).slice(0, 10);
  const cnpjPrestador = zeros(p.prestador.cnpj, 14);
  const aliquota = (Number(p.prestador.aliquota_iss || 0) / 100).toFixed(4);

  const tomadorCpfCnpj = tomadorCnpj
    ? `<CPFCNPJTomador><CNPJ>${tomadorCnpj}</CNPJ></CPFCNPJTomador>`
    : tomadorCpf
      ? `<CPFCNPJTomador><CPF>${tomadorCpf}</CPF></CPFCNPJTomador>`
      : "";

  return `<?xml version="1.0" encoding="UTF-8"?>
<PedidoEnvioRPS xmlns="http://www.prefeitura.sp.gov.br/nfe" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<Cabecalho xmlns="" Versao="1"><CPFCNPJRemetente><CNPJ>${cnpjPrestador}</CNPJ></CPFCNPJRemetente></Cabecalho>
<RPS xmlns="">
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
${p.tomador?.cep ? `<EnderecoTomador><CEP>${digitos(p.tomador.cep)}</CEP><Logradouro>${xmlEsc(p.tomador.endereco)}</Logradouro><Cidade>3550308</Cidade><UF>SP</UF></EnderecoTomador>` : ""}
${p.tomador?.email ? `<EmailTomador>${xmlEsc(p.tomador.email)}</EmailTomador>` : ""}
<Discriminacao>${xmlEsc(p.servico.discriminacao)}</Discriminacao>
</RPS>
</PedidoEnvioRPS>`;
}

function assinarXml(xml, keyPem, certPem) {
  const sig = new SignedXml({
    privateKey: keyPem,
    publicCert: certPem,
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  });
  sig.addReference({
    xpath: "/*",
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ],
  });
  sig.computeSignature(xml, { location: { reference: "/*", action: "append" } });
  return sig.getSignedXml();
}

// ───────────────────────── SOAP ─────────────────────────

function soapEnvelope(operacao, xmlPedido) {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><${operacao} xmlns="http://www.prefeitura.sp.gov.br/nfe"><VersaoSchema>1</VersaoSchema><MensagemXML><![CDATA[${xmlPedido}]]></MensagemXML></${operacao}></soap:Body>
</soap:Envelope>`;
}

function chamarPrefeitura({ ambiente, operacao, xmlPedido, pfxBuffer, senha }) {
  const url = new URL(ENDPOINTS[ambiente === "producao" ? "producao" : "homologacao"]);
  const body = Buffer.from(soapEnvelope(operacao, xmlPedido), "utf8");
  const options = {
    method: "POST",
    host: url.hostname,
    path: url.pathname,
    port: 443,
    pfx: pfxBuffer,
    passphrase: senha,
    headers: {
      "Content-Type": "text/xml; charset=utf-8",
      "Content-Length": body.length,
      SOAPAction: `http://www.prefeitura.sp.gov.br/nfe/${operacao}`,
    },
  };
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode || 0, body: Buffer.concat(chunks).toString("utf8") }),
      );
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
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
  try {
    const p = req.body || {};
    const { keyPem, certPem, pfxBuffer } = lerCertificado(
      p.certificado?.pfx_base64,
      p.certificado?.senha,
    );
    const xml = assinarXml(xmlEnvioRps(p, keyPem), keyPem, certPem);
    const r = await chamarPrefeitura({
      ambiente: p.ambiente,
      operacao: "EnvioRPS",
      xmlPedido: xml,
      pfxBuffer,
      senha: p.certificado.senha,
    });
    const info = interpretarRetorno(r.body);
    if (r.status !== 200 || !info.sucesso) {
      return res.status(422).json({ erro: info.erro || `HTTP ${r.status}`, xml_retorno: r.body.slice(0, 4000) });
    }
    res.json({
      numero_nfse: info.numero,
      codigo_verificacao: info.codigo,
      link: info.numero
        ? `https://nfe.prefeitura.sp.gov.br/contribuinte/notaprint.aspx?inscricao=${zeros(p.prestador.inscricao_municipal, 8)}&nf=${info.numero}&verificacao=${info.codigo || ""}`
        : null,
      xml_retorno: r.body.slice(0, 8000),
    });
  } catch (e) {
    res.status(500).json({ erro: e?.message || String(e) });
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
