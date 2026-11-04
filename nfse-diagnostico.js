/**
 * Diagnostico fiscal sem dados pessoais, conteudo XML, RPS ou segredos.
 * HTTP 200 indica transporte SOAP; nao confirma que a NFS-e existe.
 */
export function resumirConsultaNfse(http, xml, interpretado = {}) {
  const texto = String(xml ?? "");
  const semEntidades = texto.replace(/&lt;/gi, "<").replace(/&gt;/gi, ">");
  const codigo = /<(?:[\w.-]+:)?Codigo\s*>\s*([A-Z]?[0-9]{1,6})\s*<\/(?:[\w.-]+:)?Codigo\s*>/i.exec(semEntidades)?.[1] ?? null;
  const soapFault = /<(?:[\w.-]+:)?Fault(?:\s|>)/i.test(semEntidades);
  const sucesso = interpretado?.sucesso === true;
  const numeroPresente = Boolean(interpretado?.numero);
  return {
    http_prefeitura: Number(http) || null,
    bytes_resposta: Buffer.byteLength(texto, "utf8"),
    soap_fault: soapFault,
    sucesso_prefeitura: sucesso,
    numero_nfse_presente: numeroPresente,
    codigo_verificacao_presente: Boolean(interpretado?.codigo),
    codigo_prefeitura: codigo,
    resultado: soapFault
      ? "FALHA_SOAP"
      : sucesso && numeroPresente
        ? "NFS_E_LOCALIZADA"
        : codigo
          ? "RETORNO_COM_CODIGO_MUNICIPAL"
          : "SEM_CONFIRMACAO_DA_NFS_E",
  };
}
