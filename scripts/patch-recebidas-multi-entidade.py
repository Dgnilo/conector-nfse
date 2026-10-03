from pathlib import Path

p = Path('server.js')
s = p.read_text()

if 'function cpfCnpjXml(doc)' in s:
    raise SystemExit(0)

start = s.find('function xmlConsultaNFeRecebidas(p) {')
end = s.find('\nfunction objetosPorNome', start)
if start < 0 or end < 0:
    raise SystemExit('Bloco xmlConsultaNFeRecebidas não localizado')

replacement = r'''function cpfCnpjXml(doc) {
  const d = digitos(doc);
  if (d.length === 11) return `<CPF>${d}</CPF>`;
  if (d.length === 14) return `<CNPJ>${d}</CNPJ>`;
  throw new Error("CPF/CNPJ da consulta de NFS-e recebidas inválido.");
}

function xmlConsultaNFeRecebidas(p) {
  const tomadorDoc = digitos(p.tomador?.cpf || p.tomador?.cnpj || p.tomador?.cpf_cnpj);
  const remetenteDoc = digitos(
    p.remetente?.cpf || p.remetente?.cnpj || p.remetente?.cpf_cnpj || tomadorDoc,
  );
  const ccm = digitos(p.tomador?.inscricao_municipal || p.prestador?.inscricao_municipal);
  const inicio = so(p.data_inicio).slice(0, 10);
  const fim = so(p.data_fim).slice(0, 10);
  const pagina = Math.max(1, Number(p.pagina || 1));
  if (!/^\d{4}-\d{2}-\d{2}$/.test(inicio) || !/^\d{4}-\d{2}-\d{2}$/.test(fim)) {
    throw new Error("data_inicio e data_fim devem estar no formato AAAA-MM-DD.");
  }
  return `<?xml version="1.0" encoding="UTF-8"?>
<PedidoConsultaNFePeriodo xmlns="http://www.prefeitura.sp.gov.br/nfe">
<Cabecalho xmlns="" Versao="1">
<CPFCNPJRemetente>${cpfCnpjXml(remetenteDoc)}</CPFCNPJRemetente>
<CPFCNPJ>${cpfCnpjXml(tomadorDoc)}</CPFCNPJ>
${ccm ? `<Inscricao>${zeros(ccm, 8)}</Inscricao>` : ""}
<dtInicio>${inicio}</dtInicio>
<dtFim>${fim}</dtFim>
<NumeroPagina>${pagina}</NumeroPagina>
</Cabecalho>
</PedidoConsultaNFePeriodo>`;
}
'''

p.write_text(s[:start] + replacement + s[end:])
