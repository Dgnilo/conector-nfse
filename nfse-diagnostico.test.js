import test from "node:test";
import assert from "node:assert/strict";
import { resumirConsultaNfse } from "./nfse-diagnostico.js";

test("HTTP 200 sem numero nao comprova a emissao", () => {
  const r = resumirConsultaNfse(200, "<Envelope><Body><Sucesso>false</Sucesso><Codigo>224</Codigo></Body></Envelope>", { sucesso: false, numero: null });
  assert.equal(r.http_prefeitura, 200);
  assert.equal(r.resultado, "RETORNO_COM_CODIGO_MUNICIPAL");
  assert.equal(r.numero_nfse_presente, false);
  assert.equal(r.codigo_prefeitura, "224");
});

test("detecta codigo municipal dentro de XML escapado", () => {
  const r = resumirConsultaNfse(200, "&lt;Codigo&gt;217&lt;/Codigo&gt;", { sucesso: false });
  assert.equal(r.codigo_prefeitura, "217");
  assert.equal(r.resultado, "RETORNO_COM_CODIGO_MUNICIPAL");
});

test("confirma apenas retorno bem sucedido com numero", () => {
  const r = resumirConsultaNfse(200, "<Sucesso>true</Sucesso>", { sucesso: true, numero: "6645", codigo: "ABC" });
  assert.equal(r.resultado, "NFS_E_LOCALIZADA");
  assert.equal(r.codigo_verificacao_presente, true);
});

test("nao expoe dados pessoais nem o numero nos logs", () => {
  const r = resumirConsultaNfse(200, "<CPF>12345678901</CPF><Nome>Paciente</Nome>", { numero: "6645", erro: "Paciente" });
  const serialized = JSON.stringify(r);
  assert.doesNotMatch(serialized, /12345678901|Paciente|6645/);
});

test("distingue falha SOAP mesmo quando HTTP e 200", () => {
  const r = resumirConsultaNfse(200, "<soap:Fault><faultstring>Falha</faultstring></soap:Fault>", {});
  assert.equal(r.resultado, "FALHA_SOAP");
});
