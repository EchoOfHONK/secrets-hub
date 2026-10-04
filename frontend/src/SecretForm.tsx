import { useState } from "react";
import { WandSparkles, Upload, Plus, Terminal } from "lucide-react";
import { request, fileBase64 } from "./api";
import { Modal, Field, ErrorBox, TypeIcon, submit, safeError } from "./ui";
import { TYPES, type Secret, type SecretType, type Collection } from "./types";
import { FIELDS } from "./fields";
export function Generator({
  onClose,
  onUse,
}: {
  onClose: () => void;
  onUse: (value: string) => void;
}) {
  const [kind, setKind] = useState("password"),
    [length, setLength] = useState(24),
    [words, setWords] = useState(6),
    [opts, setOpts] = useState({
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
      exclude_ambiguous: true,
    }),
    [value, setValue] = useState(""),
    [error, setError] = useState("");
  return (
    <Modal title="Generator" onClose={onClose}>
      <form
        onSubmit={submit(async () => {
          try {
            const r = await request<{ value: string }>("/generate", {
              kind,
              length,
              words,
              ...opts,
            });
            setValue(r.value);
            setError("");
          } catch (e) {
            setError(safeError(e));
          }
        })}
      >
        <Field label="Тип">
          <select
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setValue("");
            }}
          >
            <option value="password">Password</option>
            <option value="passphrase">Passphrase</option>
            <option value="token">API token</option>
          </select>
        </Field>
        {kind === "passphrase" ? (
          <Field label="Количество слов">
            <input
              type="number"
              min={6}
              max={12}
              value={words}
              onChange={(e) => setWords(Number(e.target.value))}
            />
          </Field>
        ) : (
          <Field label="Длина">
            <input
              type="number"
              min={12}
              max={256}
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
            />
          </Field>
        )}
        {kind === "password" &&
          Object.entries(opts).map(([key, v]) => (
            <label key={key} className="checkbox">
              <input
                type="checkbox"
                checked={v}
                onChange={(e) => setOpts({ ...opts, [key]: e.target.checked })}
              />
              {
                {
                  uppercase: "A–Z",
                  lowercase: "a–z",
                  numbers: "0–9",
                  symbols: "Символы",
                  exclude_ambiguous: "Исключить похожие символы",
                }[key]
              }
            </label>
          ))}
        <ErrorBox error={error} />
        <button className="button">
          <WandSparkles size={16} /> Сгенерировать
        </button>
      </form>
      {value && (
        <>
          <Field label="Результат">
            <textarea className="mono" readOnly value={value} />
          </Field>
          <button
            className="button primary"
            onClick={() => {
              onUse(value);
              onClose();
            }}
          >
            Использовать
          </button>
        </>
      )}
    </Modal>
  );
}
export function SecretForm({
  collections,
  existing,
  initialData,
  initialType,
  initialCollection,
  onClose,
  onSaved,
}: {
  collections: Collection[];
  existing?: Secret;
  initialData?: Record<string, string>;
  initialType?: SecretType;
  initialCollection?: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [type, setType] = useState<SecretType | null>(
      existing?.type || initialType || null,
    ),
    [name, setName] = useState(existing?.name || ""),
    [collection, setCollection] = useState(
      existing?.collection_id || initialCollection || "",
    ),
    [tags, setTags] = useState(existing?.tags.join(", ") || ""),
    [expires, setExpires] = useState(existing?.expires_at?.slice(0, 10) || ""),
    [metaNote, setMetaNote] = useState(existing?.metadata.notes || ""),
    [data, setData] = useState<Record<string, string>>(initialData || {}),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [generate, setGenerate] = useState<string | null>(null),
    [sshGen, setSshGen] = useState(false);
  const multiPeer =
    type === "wireguard" && (data.config?.match(/\[Peer\]/g)?.length || 0) > 1;
  async function save() {
    if (!type) return;
    setError("");
    setBusy(true);
    try {
      if (type === "file" && !data.content_base64)
        throw new Error("Выберите файл");
      const metadata: Record<string, string> = { notes: metaNote };
      for (const key of [
        "username",
        "hostname",
        "service",
        "host",
        "endpoint",
        "address",
        "fingerprint",
        "environment",
      ])
        if (data[key]) metadata[key === "host" ? "hostname" : key] = data[key];
      if (sshGen) {
        await request("/ssh/generate", {
          name,
          host: data.host || "",
          username: data.username || "",
          passphrase: data.passphrase || undefined,
          collection_id: collection || null,
          tags: tags
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean),
          expires_at: expires ? expires + "T23:59:59Z" : null,
          metadata,
        });
      } else {
        await request(
          "/secrets" + (existing ? "/" + existing.id : ""),
          {
            name,
            type,
            collection_id: collection || null,
            tags: tags
              .split(",")
              .map((t) => t.trim())
              .filter(Boolean),
            expires_at: expires ? expires + "T23:59:59Z" : null,
            metadata,
            data,
          },
          existing ? "PUT" : "POST",
        );
      }
      onSaved();
    } catch (e) {
      setError(safeError(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={
        existing
          ? "Редактировать секрет"
          : type
            ? "New " + TYPES[type]
            : "New Secret"
      }
      wide
      onClose={onClose}
    >
      {!type ? (
        <>
          <p className="muted">Выберите, что хотите сохранить.</p>
          <div className="type-grid">
            {Object.entries(TYPES).map(([key, label]) => (
              <button
                className="type-choice"
                key={key}
                onClick={() => setType(key as SecretType)}
              >
                <span className={"secret-icon " + key}>
                  <TypeIcon type={key as SecretType} size={24} />
                </span>
                <strong>{label}</strong>
                <span>
                  {
                    {
                      login: "Пароль и учётная запись",
                      api_key: "Доступ к сервису",
                      token: "Токен приложения",
                      ssh_key: "Ключ доступа к серверу",
                      wireguard: "VPN-конфигурация",
                      environment: "Переменные окружения",
                      certificate: "Сертификат и ключ",
                      note: "Произвольный текст",
                      file: "Файл до 2 MiB",
                    }[key]
                  }
                </span>
              </button>
            ))}
          </div>
        </>
      ) : (
        <form onSubmit={submit(save)}>
          <div className="form-grid">
            <Field label="Name">
              <input
                autoFocus
                required
                maxLength={160}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <Field label="Collection">
              <select
                value={collection}
                onChange={(e) => setCollection(e.target.value)}
              >
                <option value="">Личное хранилище</option>
                {collections
                  .filter((c) => c.can_edit || c.id === collection)
                  .map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
              </select>
            </Field>
          </div>
          {type === "ssh_key" && !existing && (
            <label className="checkbox">
              <input
                type="checkbox"
                checked={sshGen}
                onChange={(e) => setSshGen(e.target.checked)}
              />
              <Terminal size={16} /> Сгенерировать новую пару Ed25519
            </label>
          )}
          {multiPeer && (
            <div className="warning-box">
              В конфигурации несколько Peer. Изменяйте полный .conf, чтобы
              сохранить все подключения.
            </div>
          )}
          {FIELDS[type]
            .filter(
              (f) =>
                !sshGen || ["host", "username", "passphrase"].includes(f.key),
            )
            .map((f) => (
              <Field
                key={f.key}
                label={f.label}
                hint={
                  [
                    "username",
                    "host",
                    "hostname",
                    "service",
                    "endpoint",
                    "address",
                    "fingerprint",
                    "environment",
                  ].includes(f.key)
                    ? "Сохраняется также в метаданных для поиска."
                    : undefined
                }
              >
                <div className="input-action">
                  {f.multiline ? (
                    <textarea
                      className="mono"
                      rows={
                        f.key === "config" || f.key === "private_key" ? 7 : 4
                      }
                      spellCheck={false}
                      autoComplete="off"
                      disabled={
                        multiPeer && !["config", "notes"].includes(f.key)
                      }
                      required={!f.optional && type !== "wireguard"}
                      value={data[f.key] || ""}
                      onChange={(e) =>
                        setData({
                          ...data,
                          [f.key]: e.target.value,
                          ...(type === "wireguard" &&
                          !["config", "notes"].includes(f.key)
                            ? { config: "" }
                            : {}),
                        })
                      }
                    />
                  ) : (
                    <input
                      type={f.sensitive ? "password" : "text"}
                      autoComplete="off"
                      disabled={
                        multiPeer && !["config", "notes"].includes(f.key)
                      }
                      required={!f.optional && type !== "wireguard"}
                      value={data[f.key] || ""}
                      onChange={(e) =>
                        setData({
                          ...data,
                          [f.key]: e.target.value,
                          ...(type === "wireguard" &&
                          !["config", "notes"].includes(f.key)
                            ? { config: "" }
                            : {}),
                        })
                      }
                    />
                  )}
                  {[
                    "password",
                    "secret",
                    "token",
                    "passphrase",
                    "key",
                  ].includes(f.key) && (
                    <button
                      type="button"
                      className="icon-button"
                      title="Сгенерировать"
                      aria-label="Сгенерировать"
                      onClick={() => setGenerate(f.key)}
                    >
                      <WandSparkles size={18} />
                    </button>
                  )}
                </div>
              </Field>
            ))}
          {type === "file" && (
            <Field
              label="Файл"
              hint="Файл шифруется до записи в базу. Максимум 2 MiB."
            >
              <input
                type="file"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  if (file.size > 2097152) {
                    setError("Максимальный размер — 2 MiB");
                    return;
                  }
                  setData({
                    filename: file.name,
                    content_type: file.type || "application/octet-stream",
                    content_base64: await fileBase64(file),
                  });
                }}
              />
            </Field>
          )}
          {type === "wireguard" && (
            <button
              type="button"
              className="button"
              disabled={!data.config}
              onClick={async () => {
                try {
                  const result = await request<{
                    data: Record<string, string>;
                  }>("/wireguard/parse", { content: data.config });
                  setData({ ...data, ...result.data });
                  setError("");
                } catch (e) {
                  setError(safeError(e));
                }
              }}
            >
              <Upload size={16} /> Заполнить из .conf
            </button>
          )}
          <div className="form-grid">
            <Field label="Tags" hint="Через запятую, например production, vpn">
              <input value={tags} onChange={(e) => setTags(e.target.value)} />
            </Field>
            <Field label="Expires">
              <input
                type="date"
                value={expires}
                onChange={(e) => setExpires(e.target.value)}
              />
            </Field>
          </div>
          <Field
            label="Заметка для поиска"
            hint="Эта заметка — незашифрованные метаданные. Не вводите пароли или ключи."
          >
            <input
              value={metaNote}
              onChange={(e) => setMetaNote(e.target.value)}
            />
          </Field>
          <ErrorBox error={error} />
          <div className="form-actions">
            {!existing && !initialType && (
              <button
                type="button"
                className="button"
                onClick={() => setType(null)}
              >
                Выбрать другой тип
              </button>
            )}
            <button disabled={busy} className="button primary">
              <Plus size={16} />
              {busy
                ? "Сохранение…"
                : existing
                  ? "Сохранить изменения"
                  : "Создать секрет"}
            </button>
          </div>
        </form>
      )}
      {generate && (
        <Generator
          onClose={() => setGenerate(null)}
          onUse={(v) => setData({ ...data, [generate]: v })}
        />
      )}
    </Modal>
  );
}
export function ImportDialog({
  collections,
  onClose,
  onSaved,
  initialFormat = "json",
}: {
  collections: Collection[];
  onClose: () => void;
  onSaved: () => void;
  initialFormat?: string;
}) {
  const [format, setFormat] = useState(initialFormat),
    [content, setContent] = useState(""),
    [name, setName] = useState(""),
    [collection, setCollection] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [passphrase, setPassphrase] = useState("");
  return (
    <Modal title="Импорт секретов" wide onClose={onClose}>
      <form
        onSubmit={submit(async () => {
          setBusy(true);
          try {
            await request("/import", {
              format,
              content,
              name,
              collection_id: collection || null,
              passphrase: passphrase || undefined,
            });
            onSaved();
          } catch (e) {
            setError(safeError(e));
          } finally {
            setBusy(false);
          }
        })}
      >
        <div className="form-grid">
          <Field label="Формат">
            <select value={format} onChange={(e) => setFormat(e.target.value)}>
              <option value="json">JSON (Secrets Hub)</option>
              <option value="csv">CSV</option>
              <option value="env">.env</option>
              <option value="ssh">SSH private key</option>
              <option value="wireguard">WireGuard .conf</option>
            </select>
          </Field>
          <Field label="Collection">
            <select
              value={collection}
              onChange={(e) => setCollection(e.target.value)}
            >
              <option value="">Личное хранилище</option>
              {collections
                .filter((c) => c.can_edit)
                .map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
            </select>
          </Field>
        </div>
        <Field label="Название (для одного секрета)">
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Файл">
          <input
            type="file"
            accept={
              format === "wireguard"
                ? ".conf"
                : format === "env"
                  ? ".env"
                  : undefined
            }
            onChange={async (e) => {
              const f = e.target.files?.[0];
              if (f) {
                if (f.size > 2097152) {
                  setError("Файл слишком большой");
                  return;
                }
                setContent(await f.text());
                if (!name) setName(f.name);
              }
            }}
          />
        </Field>
        {format === "ssh" && (
          <Field label="SSH passphrase (если ключ зашифрован)">
            <input
              type="password"
              autoComplete="off"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
            />
          </Field>
        )}
        <Field label="Содержимое">
          <textarea
            required
            className="mono"
            autoComplete="off"
            spellCheck={false}
            rows={10}
            value={content}
            onChange={(e) => setContent(e.target.value)}
          />
        </Field>
        <p className="muted">
          Импорт выполняется одной операцией. Форматы и поля CSV описаны в
          README.
        </p>
        <ErrorBox error={error} />
        <div className="form-actions">
          <button disabled={busy} className="button primary">
            <Upload size={16} />
            {busy ? "Импорт…" : "Импортировать"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
