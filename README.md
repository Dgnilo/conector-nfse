# Conector próprio NFS-e São Paulo (sem custo por nota)

Serviço Node.js que recebe as requisições do BI (Configurações fiscais → Emissor = "Conector próprio") e fala com o web service da Prefeitura de São Paulo usando **TLS mútuo com o certificado A1** e **assinatura XML RSA-SHA1**.

## 1. Rodar localmente (teste)

```bash
cd conector-nfse
npm install
CONECTOR_TOKEN="gere-um-segredo-forte" npm start
# -> http://localhost:8787
```

## 2. Publicar

Qualquer host **Node.js** serve.

### Render.com

1. Crie/conecte o repositório GitHub do conector.
2. Crie um **Web Service** com runtime Node.
3. Use `npm install` como build e `npm start` como start.
4. Em **Environment Variables**, cadastre `CONECTOR_TOKEN` com um segredo forte gerado fora do repositório.
5. Nunca grave o valor real de `CONECTOR_TOKEN`, certificados, senhas ou chaves no GitHub.

O certificado **não** fica no conector: o BI envia o PFX cifrado no corpo da requisição quando necessário.

## 3. Ligar no BI

Em **/ebrain/nfse-config**:

- Emissor: `Conector próprio`
- URL: URL HTTPS do serviço publicado
- Token: o mesmo `CONECTOR_TOKEN` configurado como segredo no host
- Ambiente: conforme a operação fiscal configurada

## 4. Endpoints

- `GET  /health` → `{ ok: true }`
- `POST /nfse/emitir` → emite um RPS (EnvioRPS)
- `POST /nfse/consultar` → consulta por número de RPS
- `POST /nfse/cancelar` → cancela NFS-e

Todos os endpoints protegidos exigem `Authorization: Bearer <CONECTOR_TOKEN>`.

## 5. Segurança operacional

- Nunca grave tokens, senhas, certificados, PFX ou chaves privadas no repositório.
- Se qualquer segredo tiver sido publicado em Git ou documentação, trate-o como comprometido e **rotacione-o no provedor e no BI**.
- O conector deve receber credenciais somente por variáveis de ambiente ou pelo cofre criptografado do BI.
- Falhas indeterminadas de transmissão fiscal não devem ser reenviadas automaticamente.

## 6. Diagnóstico

`GET /health` deve responder `{ "ok": true }`.

O serviço também possui rotas autenticadas de diagnóstico que não emitem NFS-e; use-as antes de qualquer teste fiscal real.

## Human SMS Gateway

O mesmo serviço executa o gateway próprio de SMS do Cockpit Comercial.

### Operação

A rota de telecomunicação é configurada em `Cockpit Comercial > SMS > Configurações`.

Existem dois modos:

- **Simulador**: valida fila, DLR, opt-out e relatórios sem enviar SMS real.
- **SMPP**: usa a rota A2P contratada para produção.

As credenciais SMPP ficam criptografadas no banco do Human Clinic BI e são descriptografadas apenas no backend. Em cada teste/envio, o BI transmite a configuração ao conector por HTTPS e ela permanece somente em memória. Portanto, **não cadastrar host, usuário ou senha SMPP no GitHub ou no Render**.

- O Sender ID/número precisa ser homologado para a rota A2P utilizada.
- Mensagens longas são rastreadas por segmento.
- Falhas indeterminadas não são reenviadas automaticamente.
- Opt-out por resposta e por link individual alimenta a lista de bloqueio.
- Após restart, o gateway inicia em modo `idle` e só processa mensagens depois que o Cockpit injeta uma configuração válida.
