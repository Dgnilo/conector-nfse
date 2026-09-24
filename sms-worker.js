import { client } from "@larvit/smpp";

const DEFAULT_BI_BASE =
  "https://project--ed9f90bf-a256-4657-90c6-6edd42431c41.lovable.app";

const GSM7_BASIC =
  "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";
const GSM7_EXT = "^{}\\[~]|€";

function estimateSegments(text) {
  let septets = 0;
  let gsm = true;

  for (const ch of String(text || "")) {
    if (GSM7_BASIC.includes(ch)) septets += 1;
    else if (GSM7_EXT.includes(ch)) septets += 2;
    else {
      gsm = false;
      break;
    }
  }

  if (gsm) return septets <= 160 ? 1 : Math.ceil(septets / 153);

  let units = 0;
  for (const ch of Array.from(String(text || ""))) {
    units += ch.length;
  }
  return units <= 70 ? 1 : Math.ceil(units / 67);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function mapDlrStatus(value) {
  const s = String(value || "").toUpperCase();
  if (/DELIVERED|DELIVRD/.test(s)) return "delivered";
  if (/UNDELIVERABLE|UNDELIV|EXPIRED|REJECTED|REJECTD|DELETED|UNKNOWN|FAILED/.test(s)) {
    return "failed";
  }
  if (/ACCEPTED|ENROUTE|SCHEDULED/.test(s)) return "submitted";
  return null;
}

export function installSmsGateway(app, { token }) {
  const BI_BASE_URL = String(process.env.BI_BASE_URL || DEFAULT_BI_BASE).replace(/\/$/, "");
  const MODE = String(process.env.SMS_TRANSPORT || "simulator").toLowerCase();
  const BATCH = Math.max(1, Math.min(Number(process.env.SMS_BATCH_SIZE || 50), 500));
  const TPS = Math.max(1, Number(process.env.SMS_TPS || 10));
  const POLL_MS = Math.max(1000, Number(process.env.SMS_POLL_INTERVAL_MS || 5000));

  let session = null;
  let connected = MODE === "simulator";
  let connecting = null;
  let working = false;

  async function post(path, body) {
    const response = await fetch(BI_BASE_URL + path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sms-gateway-token": token,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(path + " -> HTTP " + response.status + " " + text.slice(0, 200));
    }

    return response.json().catch(() => ({}));
  }

  async function report(body) {
    try {
      await post("/api/public/sms/dlr", body);
    } catch (error) {
      console.error("[SMS][DLR] callback falhou:", error?.message || String(error));
    }
  }

  async function inbound(body) {
    try {
      await post("/api/public/sms/inbound", body);
    } catch (error) {
      console.error("[SMS][INBOUND] callback falhou:", error?.message || String(error));
    }
  }

  async function ensureSession() {
    if (MODE === "simulator") return null;
    if (MODE !== "smpp") throw new Error("SMS_TRANSPORT inválido: " + MODE);
    if (session && connected) return session;
    if (connecting) return connecting;

    const host = String(process.env.SMPP_HOST || "").trim();
    const username = String(process.env.SMPP_SYSTEM_ID || "").trim();
    const password = String(process.env.SMPP_PASSWORD || "");

    if (!host || !username || !password) {
      throw new Error("Credenciais SMPP não configuradas.");
    }

    connecting = (async () => {
      const result = await client({
        host,
        port: Number(process.env.SMPP_PORT || 2775),
        username,
        password,
        bindType: "transceiver",
        systemType: String(process.env.SMPP_SYSTEM_TYPE || ""),
        tls: String(process.env.SMPP_TLS || "").toLowerCase() === "true",
        enquireLinkInterval: 20000,
        responseTimeout: 30000,
        maxOutstanding: Math.max(1, Math.min(Number(process.env.SMPP_WINDOW || 10), 50)),
      });

      if (result.err || !result.session) {
        connected = false;
        throw result.err || new Error("Falha ao criar sessão SMPP.");
      }

      session = result.session;
      connected = true;

      session.on("disconnected", () => {
        connected = false;
        console.warn("[SMS][SMPP] conexão interrompida; biblioteca tentará reconectar.");
      });

      session.on("reconnected", () => {
        connected = true;
        console.log("[SMS][SMPP] conexão restabelecida.");
      });

      session.on("close", () => {
        connected = false;
        session = null;
        console.warn("[SMS][SMPP] sessão encerrada.");
      });

      session.on("sessionError", (error) => {
        console.error("[SMS][SMPP] erro de sessão:", error?.message || String(error));
      });

      session.on("dlr", async (dlr) => {
        const status = mapDlrStatus(dlr?.statusMsg);
        if (!status || !dlr?.smsId) return;

        await report({
          provider_message_id: String(dlr.smsId),
          status,
          raw_status: dlr.statusMsg ?? null,
          status_id: dlr.statusId ?? null,
          intermediate: Boolean(dlr.intermediate),
        });
      });

      session.on("sms", async (sms) => {
        try {
          await inbound({
            from: String(sms?.from || ""),
            to: String(sms?.to || ""),
            text: String(sms?.message || ""),
            provider_message_id: sms?.smsId ? String(sms.smsId) : null,
          });
        } finally {
          try {
            await sms.sendResp();
          } catch (error) {
            console.error("[SMS][SMPP] falha ao responder MO:", error?.message || String(error));
          }
        }
      });

      console.log("[SMS][SMPP] sessão conectada em", host);
      return session;
    })();

    try {
      return await connecting;
    } finally {
      connecting = null;
    }
  }

  async function submit(message) {
    const logicalId = String(message.id);

    if (MODE === "simulator") {
      const count = Math.max(1, estimateSegments(message.mensagem_final));
      const ids = Array.from(
        { length: count },
        (_, index) =>
          "sim-" +
          Date.now() +
          "-" +
          logicalId.slice(0, 8) +
          "-" +
          (index + 1),
      );

      await report({
        client_ref: logicalId,
        provider_message_ids: ids,
        status: "submitted",
      });

      setTimeout(() => {
        for (const id of ids) {
          void report({
            provider_message_id: id,
            status: "delivered",
          });
        }
      }, 350);

      return;
    }

    const smpp = await ensureSession();
    const result = await smpp.sendSms(
      {
        from:
          String(message.sender_id || process.env.SMPP_SOURCE_ADDR || "HUMANCLINIC"),
        to: String(message.telefone_e164),
        message: String(message.mensagem_final),
        dlr: true,
        maxSegments: Math.max(1, Math.min(Number(process.env.SMS_MAX_SEGMENTS || 10), 20)),
      },
      { signal: AbortSignal.timeout(45000) },
    );

    const acceptedIds = (result.smsIds || [])
      .map((id) => (id == null ? "" : String(id)))
      .filter(Boolean);

    if (result.err || Number(result.unanswered || 0) > 0) {
      const accepted = acceptedIds.length > 0;
      await report({
        client_ref: logicalId,
        status: "failed",
        error:
          (accepted ? "INDETERMINADO - NÃO REENVIAR AUTOMATICAMENTE. " : "") +
          String(result.err?.message || "SMSC não respondeu a todos os segmentos."),
        provider_message_ids: acceptedIds,
        unanswered: Number(result.unanswered || 0),
      });
      return;
    }

    if (!acceptedIds.length) {
      await report({
        client_ref: logicalId,
        status: "failed",
        error:
          "INDETERMINADO - NÃO REENVIAR AUTOMATICAMENTE. SMSC aceitou o envio sem retornar message_id.",
      });
      return;
    }

    await report({
      client_ref: logicalId,
      provider_message_ids: acceptedIds,
      status: "submitted",
    });
  }

  async function pollOnce() {
    const response = await post("/api/public/sms/queue", { limit: BATCH });
    const messages = response.messages || [];

    for (const message of messages) {
      try {
        await submit(message);
      } catch (error) {
        await report({
          client_ref: String(message.id),
          status: "failed",
          error: error?.message || String(error),
        });
      }

      await sleep(Math.ceil(1000 / TPS));
    }

    return messages.length;
  }

  async function kick() {
    if (working || !token || !BI_BASE_URL) return;
    working = true;

    try {
      if (MODE === "smpp") await ensureSession();

      for (let round = 0; round < 200; round++) {
        const count = await pollOnce();
        if (!count) break;
      }
    } catch (error) {
      console.error("[SMS][WORKER]", error?.message || String(error));
    } finally {
      working = false;
    }
  }

  app.get("/sms/health", async (_req, res) => {
    let routeReady = MODE === "simulator";

    if (MODE === "smpp") {
      try {
        await ensureSession();
        routeReady = connected;
      } catch {
        routeReady = false;
      }
    }

    res.json({
      ok: true,
      service: "human-sms-gateway",
      mode: MODE,
      connected: routeReady,
      worker_busy: working,
      tps: TPS,
      batch: BATCH,
      bi_configured: Boolean(BI_BASE_URL),
      smpp_configured:
        MODE === "simulator" ||
        Boolean(
          process.env.SMPP_HOST &&
            process.env.SMPP_SYSTEM_ID &&
            process.env.SMPP_PASSWORD,
        ),
    });
  });

  app.post("/sms/process", (_req, res) => {
    void kick();
    res.status(202).json({
      ok: true,
      accepted: true,
      mode: MODE,
      worker_busy: true,
    });
  });

  // Enquanto o serviço estiver acordado, continua drenando a fila.
  setInterval(() => {
    void kick();
  }, POLL_MS);

  console.log("[SMS] Human SMS Gateway instalado em modo", MODE);
}
