# Conector próprio NFS-e São Paulo (sem custo por nota)

Serviço Node.js que recebe as requisições do BI (Configurações fiscais → Emissor = "Conector próprio")
e fala com o web service da Prefeitura de São Paulo usando **TLS mútuo com o certificado A1** e
**assinatura XML RSA-SHA1** — as duas coisas que o runtime do app não suporta.

## 1. Rodar localmente (teste)

```bash
cd conector-nfse
npm install
CONECTOR_TOKEN="um-segredo-forte" npm start
# -> http://localhost:8787
```

## 2. Publicar de graça

Qualquer host **Node.js** serve. O conector NÃO roda em Python — certifique-se de escolher runtime Node.

### Render.com (recomendado, gratuito)

1. Crie um repositório no GitHub com o conteúdo desta pasta (`conector-nfse`).
2. Acesse https://dashboard.render.com/ → **New +** → **Web Service**.
3. Conecte o repositório `Dgnilo/conector-nfse` (ou o seu).
4. Preencha EXATAMENTE assim:

   | Campo | Valor |
   |---|---|
   | **Name** | `conector-nfse` |
   | **Runtime** | `Node` ⚠️ (Render às vezes sugere Python — mude para Node) |
   | **Root Directory** | deixe em branco (repo só tem essa pasta) |
   | **Build Command** | `npm install` |
   | **Start Command** | `npm start` |
   | **Plan** | Free |

5. Em **Environment Variables** adicione:

   | Key | Value |
   |---|---|
   | `CONECTOR_TOKEN` | `w2wpfSt4JpS530sbcRass_z1mE7KVv1tVgFHavbO-aY` |

6. Clique em **Create Web Service**.

> Dica: inclua o arquivo `render.yaml` desta pasta no repo. Ele pré-configura o serviço como Node automaticamente.

### Outras opções

- **Fly.io** (free allowance): `fly launch` dentro de `conector-nfse`.
- **Railway / Koyeb / Oracle Cloud Free VM**: mesmo comando `npm start`.
- **Máquina própria/VPS da clínica**: `npm start` + proxy HTTPS (Caddy/Nginx).

Variável de ambiente obrigatória:

| Variável | Descrição |
|---|---|
| `CONECTOR_TOKEN` | Segredo compartilhado. O mesmo valor vai no campo **Token** da tela de Configurações fiscais. |
| `PORT` | Opcional (default 8787). |

O certificado **não** fica no conector: o BI envia o .pfx cifrado no corpo da requisição a cada emissão.

## 3. Ligar no BI

Em **/ebrain/nfse-config**:

- Emissor: `Conector próprio`
- URL: `https://seu-conector.onrender.com`
- Token: o mesmo `CONECTOR_TOKEN`
- Ambiente: `homologacao` para testar, depois `producao`

## 4. Endpoints

- `GET  /health` → `{ ok: true }`
- `POST /nfse/emitir` → emite um RPS (EnvioRPS)
- `POST /nfse/consultar` → consulta por número de RPS
- `POST /nfse/cancelar` → cancela NFS-e

Todos exigem `Authorization: Bearer <CONECTOR_TOKEN>`.

## 5. Homologação

A Prefeitura exige teste em homologação antes de liberar produção
(`https://nfeh.prefeitura.sp.gov.br/ws/lotenfe.asmx`). Use ambiente `homologacao`
na tela de configuração até validar o primeiro RPS.

## 6. Problemas comuns

### O deploy no Render fica com status "Python 3"

O Render às vezes detecta linguagem errada. Vá em **Settings** do serviço e altere:

- **Runtime**: `Node`
- **Build Command**: `npm install`
- **Start Command**: `npm start`

Depois clique em **Manual Deploy → Deploy latest commit**.

### `curl /health` não responde / timeout

Provavelmente o runtime está como Python ou falta `CONECTOR_TOKEN`. Verifique os logs em
**Logs** no dashboard do Render.

### A nota fica "enviando" no BI

Isso acontece quando o conector está fora do ar ou a URL está incorreta. Teste:

```bash
curl https://conector-nfse.onrender.com/health
```

Deve retornar `{ "ok": true }`. Se não retornar, revise a configuração do Render.


## Human SMS Gateway

O mesmo serviço também executa o gateway próprio de SMS do Cockpit Comercial.

### Modo de validação

Sem nenhuma credencial SMPP configurada, o gateway inicia em modo simulador:

\`\`\`
SMS_TRANSPORT=simulator
\`\`\`

Nesse modo nenhuma mensagem chega a uma operadora. A fila, os recibos de entrega, o
opt-out e o histórico são testados de ponta a ponta sem custo.

### Produção via SMPP

Para ativar SMS real, configure somente no ambiente seguro do Render (nunca no
GitHub):

\`\`\`
SMS_TRANSPORT=smpp
SMPP_HOST=
SMPP_PORT=2775
SMPP_SYSTEM_ID=
SMPP_PASSWORD=
SMPP_SYSTEM_TYPE=
SMPP_SOURCE_ADDR=HUMANCLINIC
SMPP_TLS=false
SMS_TPS=10
SMS_MAX_SEGMENTS=10
\`\`\`

O gateway usa a mesma autenticação segura do conector Human para conversar com o BI.
O endereço do BI tem fallback para a aplicação Human Clinic publicada e pode ser
sobrescrito por \`BI_BASE_URL\`.

### Segurança

- Nunca grave tokens, senhas SMPP ou certificados no repositório.
- Sender ID e rota SMPP devem ser homologados para tráfego A2P no Brasil.
- Falhas indeterminadas não são reenviadas automaticamente, evitando duplicidade.
- Respostas de opt-out e links individuais alimentam a lista de bloqueio do BI.
