import { client } from "@larvit/smpp";

const DEFAULT_BI_BASE =
  "https://humanclinicbi.lovable.app";

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
  for (const ch of Array.from(String(text || ""))) units += ch.length;
  return units <= 70 ? 1 : Math.ceil(units / 67);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function mapDlrStatus(value) {
  const status = String(value || "").toUpperCase();
  if (/DELIVERED|DELIVRD/.test(status)) return "delivered";
  if (
    /UNDELIVERABLE|UNDELIV|EXPIRED|REJECTED|REJECTD|DELETED|UNKNOWN|FAILED/.test(
      status,
    )
  ) {
    return "failed";
  }
  if (/ACCEPTED|ENROUTE|SCHEDULED/.test(status)) return "submitted";
  return null;
}

function clamp(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(n, max));
}

function normalizeRuntimeConfig(input) {
  const mode = input?.mode === "smpp" ? "smpp" : "simulator";

  return {
    mode,
    host: String(input?.host || "").trim(),
    port: clamp(input?.port, 1, 65535, 2775),
    system_id: String(input?.system_id || "").trim(),
    password: String(input?.password || ""),
    system_type: String(input?.system_type || "").trim(),
    source_addr: String(input?.source_addr || "HUMANCLINIC").trim() || "HUMANCLINIC",
    tls: Boolean(input?.tls),
    tps: clamp(input?.tps, 1, 500, 10),
    max_segments: clamp(input?.max_segments, 1, 20, 10),
  };
}

function envRuntimeConfig() {
  const explicitMode = String(process.env.SMS_TRANSPORT || "").toLowerCase();
  if (explicitMode !== "simulator" && explicitMode !== "smpp") return null;

  return normalizeRuntimeConfig({
    mode: explicitMode,
    host: process.env.SMPP_HOST,
    port: process.env.SMPP_PORT,
    system_id: process.env.SMPP_SYSTEM_ID,
    password: process.env.SMPP_PASSWORD,
    system_type: process.env.SMPP_SYSTEM_TYPE,
    source_addr: process.env.SMPP_SOURCE_ADDR,
    tls: String(process.env.SMPP_TLS || "").toLowerCase() === "true",
    tps: process.env.SMS_TPS,
    max_segments: process.env.SMS_MAX_SEGMENTS,
  });
}

export function installSmsGateway(app, { token }) {
  const BI_BASE_URL = String(
    process.env.BI_BASE_URL || DEFAULT_BI_BASE,
  ).replace(/\/$/, "");
  const BATCH = clamp(process.env.SMS_BATCH_SIZE, 1, 500, 50);
  const POLL_MS = clamp(process.env.SMS_POLL_INTERVAL_MS, 1000, 60000, 5000);

  let runtimeConfig = envRuntimeConfig();
  let session = null;
  let connected = runtimeConfig?.mode === "simulator";
  let connecting = null;
  let working = false;
  let configVersion = 0;

  function currentConfig() {
    return runtimeConfig;
  }

  function closeSession() {
    const old = session;
    session = null;
    connected = false;
    connecting = null;

    if (!old) return;

    try {
      if (typeof old.close === "function") old.close();
      else if (typeof old.destroy === "function") old.destroy();
    } catch (error) {
      console.warn(
        "[SMS][SMPP] falha ao encerrar sessão antiga:",
        error?.message || String(error),
      );
    }
  }

  function setRuntimeConfig(input) {
    const next = normalizeRuntimeConfig(input);

    if (
      next.mode === "smpp" &&
      (!next.host || !next.system_id || !next.password)
    ) {
      throw new Error(
        "Configuração SMPP incompleta: host, System ID e senha são obrigatórios.",
      );
    }

    // Nunca logar o conteúdo da configuração: ela contém a senha SMPP.
    closeSession();
    runtimeConfig = next;
    connected = next.mode === "simulator";
    configVersion += 1;

    return {
      mode: next.mode,
      configured: true,
      source_addr: next.source_addr,
      tls: next.tls,
      tps: next.tps,
      max_segments: next.max_segments,
      version: configVersion,
    };
  }

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
      throw new Error(
        path + " -> HTTP " + response.status + " " + text.slice(0, 200),
      );
    }

    return response.json().catch(() => ({}));
  }

  async function report(body) {
    try {
      await post("/api/public/sms/dlr", body);
    } catch (error) {
      console.error(
        "[SMS][DLR] callback falhou:",
        error?.message || String(error),
      );
    }
  }

  async function inbound(body) {
    try {
      await post("/api/public/sms/inbound", body);
    } catch (error) {
      console.error(
        "[SMS][INBOUND] callback falhou:",
        error?.message || String(error),
      );
    }
  }

  async function ensureSession() {
    const cfg = currentConfig();

    if (!cfg) {
      throw new Error(
        "Configuração SMS ainda não foi carregada pelo Cockpit.",
      );
    }

    if (cfg.mode === "simulator") return null;
    if (session && connected) return session;
    if (connecting) return connecting;

    const connectingVersion = configVersion;

    connecting = (async () => {
      const result = await client({
        host: cfg.host,
        port: cfg.port,
        username: cfg.system_id,
        password: cfg.password,
        bindType: "transceiver",
        systemType: cfg.system_type,
        tls: cfg.tls,
        enquireLinkInterval: 20000,
        responseTimeout: 30000,
        maxOutstanding: 10,
      });

      if (connectingVersion !== configVersion) {
        try {
          result.session?.close?.();
        } catch {}
        throw new Error(
          "Configuração SMPP mudou durante a conexão; tente novamente.",
        );
      }

      if (result.err || !result.session) {
        connected = false;
        throw result.err || new Error("Falha ao criar sessão SMPP.");
      }

      session = result.session;
      connected = true;

      session.on("disconnected", () => {
        connected = false;
        console.warn(
          "[SMS][SMPP] conexão interrompida; aguardando reconexão.",
        );
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
        console.error(
          "[SMS][SMPP] erro de sessão:",
          error?.message || String(error),
        );
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
            provider_message_id: sms?.smsId
              ? String(sms.smsId)
              : null,
          });
        } finally {
          try {
            await sms.sendResp();
          } catch (error) {
            console.error(
              "[SMS][SMPP] falha ao responder MO:",
              error?.message || String(error),
            );
          }
        }
      });

      console.log("[SMS][SMPP] sessão conectada.");
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
    const cfg = currentConfig();

    if (!cfg) {
      throw new Error("Configuração SMS não carregada.");
    }

    if (cfg.mode === "simulator") {
      const count = Math.max(
        1,
        estimateSegments(message.mensagem_final),
      );
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
        from: String(
          message.sender_id ||
            cfg.source_addr ||
            "HUMANCLINIC",
        ),
        to: String(message.telefone_e164),
        message: String(message.mensagem_final),
        dlr: true,
        maxSegments: cfg.max_segments,
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
          (accepted
            ? "INDETERMINADO - NÃO REENVIAR AUTOMATICAMENTE. "
            : "") +
          String(
            result.err?.message ||
              "SMSC não respondeu a todos os segmentos.",
          ),
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
    const cfg = currentConfig();
    if (!cfg) return 0;

    const response = await post("/api/public/sms/queue", {
      limit: BATCH,
    });
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

      await sleep(Math.ceil(1000 / cfg.tps));
    }

    return messages.length;
  }

  async function kick() {
    if (working || !token || !BI_BASE_URL || !currentConfig()) return;
    working = true;

    try {
      if (currentConfig()?.mode === "smpp") await ensureSession();

      for (let round = 0; round < 200; round++) {
        const count = await pollOnce();
        if (!count) break;
      }
    } catch (error) {
      console.error(
        "[SMS][WORKER]",
        error?.message || String(error),
      );
    } finally {
      working = false;
    }
  }

  app.get("/sms/health", async (_req, res) => {
    const cfg = currentConfig();

    res.json({
      ok: true,
      service: "human-sms-gateway",
      mode: cfg?.mode ?? "idle",
      connected:
        cfg?.mode === "simulator"
          ? true
          : cfg?.mode === "smpp"
            ? connected
            : false,
      worker_busy: working,
      tps: cfg?.tps ?? 0,
      batch: BATCH,
      bi_configured: Boolean(BI_BASE_URL),
      smpp_configured:
        cfg?.mode === "simulator" ||
        Boolean(
          cfg?.host &&
            cfg?.system_id &&
            cfg?.password,
        ),
      config_version: configVersion,
    });
  });

  app.post("/sms/process", (req, res) => {
    let applied = null;

    try {
      if (req.body?.config) {
        applied = setRuntimeConfig(req.body.config);
      } else if (!currentConfig()) {
        throw new Error(
          "Configuração SMS ausente. Abra Configurações SMS no Cockpit.",
        );
      }
    } catch (error) {
      return res.status(422).json({
        ok: false,
        error: error?.message || String(error),
      });
    }

    void kick();

    return res.status(202).json({
      ok: true,
      accepted: true,
      mode: currentConfig()?.mode ?? "idle",
      worker_busy: true,
      config: applied
        ? {
            mode: applied.mode,
            source_addr: applied.source_addr,
            tls: applied.tls,
            tps: applied.tps,
            max_segments: applied.max_segments,
            version: applied.version,
          }
        : null,
    });
  });

  // Em produção sem config em variável de ambiente, o serviço fica "idle"
  // após um restart. O Cockpit injeta a configuração descriptografada em memória
  // no primeiro teste/envio. Isso impede envio simulado acidental.
  setInterval(() => {
    if (currentConfig()) void kick();
  }, POLL_MS);

  console.log(
    "[SMS] Human SMS Gateway instalado em modo",
    currentConfig()?.mode ?? "idle",
  );
}
