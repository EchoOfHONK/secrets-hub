import { useEffect, useState } from "react";
import {
  Eye,
  EyeOff,
  Copy,
  Pencil,
  Trash2,
  History,
  Share2,
  Link,
  Download,
  GitBranch,
  RotateCcw,
} from "lucide-react";
import { request, copyText, downloadText, downloadBlob } from "./api";
import {
  Modal,
  Field,
  ErrorBox,
  TypeIcon,
  DateText,
  Expiry,
  Loading,
  safeError,
} from "./ui";
import { TYPES, type Secret, type Version } from "./types";
import { FIELDS } from "./fields";
import { AccessDialog, TemporaryDialog } from "./Sharing";
export function SecretDetail({
  secret,
  onClose,
  onEdit,
  onChanged,
  notify,
  reauth,
}: {
  secret: Secret;
  onClose: () => void;
  onEdit: (data: Record<string, string>) => void;
  onChanged: () => void;
  notify: (m: string) => void;
  reauth: (action: () => Promise<void>) => void;
}) {
  const [data, setData] = useState<Record<string, string>>({}),
    [visible, setVisible] = useState<string[]>([]),
    [error, setError] = useState(""),
    [tab, setTab] = useState("details"),
    [versions, setVersions] = useState<Version[]>([]),
    [share, setShare] = useState(false),
    [temporary, setTemporary] = useState(false),
    [config, setConfig] = useState<{
      config: string;
      qr_data_url: string | null;
    } | null>(null),
    [old, setOld] = useState<{
      version: Version;
      data: Record<string, string>;
    } | null>(null),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    const clear = setTimeout(() => {
      setData({});
      setVisible([]);
      setConfig(null);
      setOld(null);
    }, 60000);
    return () => clearTimeout(clear);
  }, [visible, config, old]);
  async function reveal(action = "view", version_id?: string) {
    const result = await request<{ data: Record<string, string> }>(
      `/secrets/${secret.id}/reveal`,
      { action, version_id },
    );
    return result.data;
  }
  async function show(key: string) {
    if (visible.includes(key)) {
      setVisible(visible.filter((x) => x !== key));
      return;
    }
    if (
      key === "private_key" &&
      !confirm(
        "Показать private key? Убедитесь, что экран не виден посторонним.",
      )
    )
      return;
    try {
      const result = await reveal();
      setData(result);
      setVisible([...visible, key]);
    } catch (e) {
      setError(safeError(e));
    }
  }
  async function copy(key: string) {
    try {
      const result = await reveal("copy");
      await copyText(result[key] || "");
      notify("Секрет скопирован в clipboard");
    } catch (e) {
      setError(safeError(e));
    }
  }
  async function loadHistory() {
    setTab("history");
    setBusy(true);
    try {
      setVersions(await request(`/secrets/${secret.id}/versions`));
    } catch (e) {
      setError(safeError(e));
    } finally {
      setBusy(false);
    }
  }
  async function getConfig(action: string) {
    try {
      const result = await request<{ config: string; qr_data_url: string }>(
        `/wireguard/${secret.id}/config`,
        { action },
      );
      if (action === "export")
        downloadText(
          result.config,
          secret.name.replace(/[^a-zA-Z0-9_-]/g, "_") + ".conf",
        );
      else setConfig(result);
    } catch (e) {
      setError(safeError(e));
    }
  }
  return (
    <Modal title={secret.name} wide onClose={onClose}>
      <div className="detail-meta">
        <span className={"secret-icon " + secret.type}>
          <TypeIcon type={secret.type} size={23} />
        </span>
        <span>{TYPES[secret.type]}</span>
        <span className="badge">Version {secret.version}</span>
        <Expiry date={secret.expires_at} />
      </div>
      <div className="tabs">
        <button
          className={tab === "details" ? "active" : ""}
          onClick={() => setTab("details")}
        >
          Details
        </button>
        <button
          className={tab === "history" ? "active" : ""}
          onClick={() => void loadHistory()}
        >
          <History size={16} /> Version History
        </button>
      </div>
      <ErrorBox error={error} />
      {tab === "details" ? (
        <>
          <div className="secret-fields">
            {FIELDS[secret.type].map((f) => (
              <div className="secret-field" key={f.key}>
                <span>{f.label}</span>
                <div className="secret-value-row">
                  <pre
                    className={
                      visible.includes(f.key) ? "secret-value" : "masked"
                    }
                  >
                    {visible.includes(f.key)
                      ? data[f.key] || "—"
                      : "••••••••••••••••"}
                  </pre>
                  <div className="secret-value-actions">
                    <button
                      className="icon-button"
                      title={visible.includes(f.key) ? "Hide" : "Show"}
                      aria-label={
                        (visible.includes(f.key) ? "Hide " : "Show ") + f.label
                      }
                      onClick={() => void show(f.key)}
                    >
                      {visible.includes(f.key) ? (
                        <EyeOff size={17} />
                      ) : (
                        <Eye size={17} />
                      )}
                    </button>
                    <button
                      className="icon-button"
                      disabled={!secret.can_copy}
                      title="Copy"
                      aria-label={"Copy " + f.label}
                      onClick={() => void copy(f.key)}
                    >
                      <Copy size={17} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
          {secret.type === "wireguard" && (
            <div className="button-row">
              <button className="button" onClick={() => void getConfig("view")}>
                Show config & QR
              </button>
              <button
                className="button"
                disabled={!secret.can_copy}
                onClick={() => reauth(() => getConfig("export"))}
              >
                <Download size={16} /> Download .conf
              </button>
            </div>
          )}
          {secret.type === "file" && (
            <button
              className="button"
              disabled={!secret.can_copy}
              onClick={() =>
                reauth(async () => {
                  try {
                    const d = await reveal("export");
                    const bytes = Uint8Array.from(atob(d.content_base64), (c) =>
                      c.charCodeAt(0),
                    );
                    downloadBlob(
                      new Blob([bytes], { type: "application/octet-stream" }),
                      d.filename || "secret-file",
                    );
                    notify("Файл скачан");
                  } catch (e) {
                    setError(safeError(e));
                  }
                })
              }
            >
              <Download size={16} /> Скачать файл
            </button>
          )}
          {secret.type === "ssh_key" && (
            <div className="button-row">
              {["public_key", "private_key"].map((key) => (
                <button
                  key={key}
                  className="button"
                  disabled={!secret.can_copy}
                  onClick={() =>
                    reauth(async () => {
                      try {
                        const d = await reveal("export");
                        downloadText(
                          d[key] || "",
                          key === "private_key"
                            ? "id_ed25519"
                            : "id_ed25519.pub",
                        );
                      } catch (e) {
                        setError(safeError(e));
                      }
                    })
                  }
                >
                  <Download size={16} />
                  {key === "private_key"
                    ? "Download private key"
                    : "Download public key"}
                </button>
              ))}
            </div>
          )}
          <div className="tag-list">
            {secret.tags.map((t) => (
              <span className="tag" key={t}>
                {t}
              </span>
            ))}
          </div>
          {secret.metadata.notes && (
            <p className="muted">Заметка для поиска: {secret.metadata.notes}</p>
          )}
          <div className="detail-dates">
            <span>
              Created <DateText value={secret.created_at} />
            </span>
            <span>
              Updated <DateText value={secret.updated_at} />
            </span>
          </div>
        </>
      ) : busy ? (
        <Loading />
      ) : (
        <div className="version-list">
          {versions.map((v) => (
            <div className="version" key={v.id}>
              <div>
                <strong>Version {v.number}</strong>
                <p>
                  <DateText value={v.created_at} /> · {v.username}
                </p>
                <span className="muted">
                  Поля: {v.changed_fields.join(", ") || "Создание"}
                </span>
              </div>
              <div className="button-row">
                <button
                  className="button small"
                  onClick={async () => {
                    try {
                      setOld({ version: v, data: await reveal("view", v.id) });
                    } catch (e) {
                      setError(safeError(e));
                    }
                  }}
                >
                  <Eye size={15} /> Show
                </button>
                <button
                  disabled={!secret.can_edit}
                  className="button small"
                  onClick={async () => {
                    if (
                      !confirm(
                        `Восстановить Version ${v.number}? Будет создана новая версия.`,
                      )
                    )
                      return;
                    try {
                      await request(`/secrets/${secret.id}/restore`, {
                        version_id: v.id,
                      });
                      notify("Версия восстановлена");
                      onChanged();
                    } catch (e) {
                      setError(safeError(e));
                    }
                  }}
                >
                  <RotateCcw size={15} /> Restore
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="detail-toolbar">
        {secret.can_edit && (
          <>
            <button
              className="button"
              onClick={async () => {
                try {
                  onEdit(await reveal());
                } catch (e) {
                  setError(safeError(e));
                }
              }}
            >
              <Pencil size={16} /> Edit
            </button>
            {secret.can_share && (
              <button className="button" onClick={() => setShare(true)}>
                <Share2 size={16} /> Share
              </button>
            )}
            <button
              className="button"
              disabled={!secret.can_copy}
              onClick={() => setTemporary(true)}
            >
              <Link size={16} /> Temporary Access
            </button>
            <button
              className="icon-button"
              title="Duplicate"
              aria-label="Duplicate"
              disabled={!secret.can_copy}
              onClick={async () => {
                try {
                  await request(`/secrets/${secret.id}/duplicate`, {});
                  notify("Создана копия");
                  onChanged();
                } catch (e) {
                  setError(safeError(e));
                }
              }}
            >
              <GitBranch size={17} />
            </button>
            <button
              className="icon-button danger-text"
              title="Delete"
              aria-label="Delete"
              onClick={async () => {
                if (
                  !confirm("Удалить секрет и всю историю? Действие необратимо.")
                )
                  return;
                try {
                  await request("/secrets/" + secret.id, {}, "DELETE");
                  notify("Секрет удалён");
                  onChanged();
                } catch (e) {
                  setError(safeError(e));
                }
              }}
            >
              <Trash2 size={17} />
            </button>
          </>
        )}
      </div>
      {share && (
        <AccessDialog
          id={secret.id}
          kind="secret"
          onClose={() => setShare(false)}
          notify={notify}
        />
      )}
      {temporary && (
        <TemporaryDialog
          secret={secret}
          onClose={() => setTemporary(false)}
          onSaved={() => notify("Временная ссылка создана")}
          notify={notify}
        />
      )}
      {config && (
        <Modal
          title="WireGuard client config"
          wide
          onClose={() => setConfig(null)}
        >
          <div className="warning-box">
            QR содержит private key. Показывайте его только доверенному
            устройству.
          </div>
          <pre className="config-output">{config.config}</pre>
          {config.qr_data_url && (
            <img
              className="qr"
              src={config.qr_data_url}
              alt="QR-код WireGuard client config"
            />
          )}
        </Modal>
      )}
      {old && (
        <Modal
          title={"Version " + old.version.number}
          wide
          onClose={() => setOld(null)}
        >
          <p className="muted">
            Значение открыто по вашему запросу. Действие записано в audit log.
          </p>
          {Object.entries(old.data)
            .filter(([k]) => k !== "content_base64")
            .map(([k, v]) => (
              <Field key={k} label={k}>
                <pre className="config-output">{v}</pre>
              </Field>
            ))}
        </Modal>
      )}
    </Modal>
  );
}
