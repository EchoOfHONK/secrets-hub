import { useEffect, useState } from "react";
import { ShieldCheck, Eye, Copy, LockKeyhole } from "lucide-react";
import { request, setCsrf, copyText, downloadBlob } from "./api";
import { Field, ErrorBox, DateText, safeError, submit } from "./ui";
import type { Session, SecretType } from "./types";
import { FIELDS } from "./fields";
export function PublicLink() {
  const [token] = useState(() => location.hash.slice(1)),
    [password, setPassword] = useState(""),
    [data, setData] = useState<{
      name: string;
      type: SecretType;
      data: Record<string, string>;
      allow_copy: boolean;
      expires_at: string;
    } | null>(null),
    [error, setError] = useState(""),
    [ready, setReady] = useState(false),
    [busy, setBusy] = useState(false),
    [notice, setNotice] = useState("");
  useEffect(() => {
    request<Session>("/auth/session")
      .then((s) => {
        setCsrf(s.csrf_token);
        setReady(true);
      })
      .catch((e) => setError(safeError(e)));
  }, []);
  useEffect(() => {
    if (!data) return;
    const timer = setTimeout(
      () => {
        setData(null);
        setPassword("");
        setError(
          "Содержимое скрыто. Одноразовую ссылку нельзя открыть повторно.",
        );
      },
      Math.min(
        300000,
        Math.max(0, new Date(data.expires_at).getTime() - Date.now()),
      ),
    );
    return () => clearTimeout(timer);
  }, [data]);
  return (
    <div className="auth-layout">
      <div className={"auth-card " + (data ? "public-card" : "")}>
        <div className="auth-brand">
          <span className="brand-mark">
            <ShieldCheck size={25} />
          </span>
          Secrets Hub
        </div>
        <div className="auth-emblem">
          <LockKeyhole size={35} />
        </div>
        <h1>{data ? data.name : "Temporary Access"}</h1>
        {data ? (
          <>
            <p>
              Доступ до <DateText value={data.expires_at} />
            </p>
            <div
              className={
                "secret-fields " + (!data.allow_copy ? "copy-disabled" : "")
              }
            >
              {FIELDS[data.type].map((f) => (
                <Field key={f.key} label={f.label}>
                  <div className="secret-value-row">
                    <pre className="secret-value">
                      {data.data[f.key] || "—"}
                    </pre>
                    {data.allow_copy && (
                      <button
                        className="icon-button"
                        aria-label={"Copy " + f.label}
                        onClick={async () => {
                          try {
                            await request("/public/temporary/copy", {
                              token,
                              password: password || undefined,
                            });
                            await copyText(data.data[f.key] || "");
                            setNotice("Секрет скопирован в clipboard");
                          } catch (e) {
                            setError(safeError(e));
                          }
                        }}
                      >
                        <Copy size={17} />
                      </button>
                    )}
                  </div>
                </Field>
              ))}
            </div>
            {data.type === "file" && data.allow_copy && (
              <button
                className="button"
                onClick={async () => {
                  try {
                    await request("/public/temporary/copy", {
                      token,
                      password: password || undefined,
                    });
                    const bytes = Uint8Array.from(
                      atob(data.data.content_base64),
                      (c) => c.charCodeAt(0),
                    );
                    downloadBlob(
                      new Blob([bytes], { type: "application/octet-stream" }),
                      data.data.filename || "secret-file",
                    );
                    setNotice("Файл скачан");
                  } catch (e) {
                    setError(safeError(e));
                  }
                }}
              >
                Скачать файл
              </button>
            )}
            {!data.allow_copy && (
              <p className="muted">
                Копирование через приложение запрещено владельцем.
              </p>
            )}
            <button
              className="button"
              onClick={() => {
                setData(null);
                setPassword("");
                setError(
                  "Содержимое скрыто. Ссылка может быть уже использована.",
                );
              }}
            >
              Скрыть содержимое
            </button>
            <p role="status" className="success-text">
              {notice}
            </p>
          </>
        ) : (
          <>
            <p>
              Открывайте только на доверенном устройстве. Нажатие «Show»
              использует один просмотр ссылки.
            </p>
            <form
              onSubmit={submit(async () => {
                setBusy(true);
                setError("");
                try {
                  const r = await request<typeof data & object>(
                    "/public/temporary",
                    { token, password: password || undefined },
                  );
                  setData(r);
                } catch (e) {
                  setError(safeError(e));
                } finally {
                  setBusy(false);
                }
              })}
            >
              <Field label="Пароль ссылки (если задан)">
                <input
                  type="password"
                  autoComplete="off"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </Field>
              <button
                disabled={!ready || busy || !token}
                className="button primary full"
              >
                <Eye size={17} />
                {busy ? "Проверка…" : "Show secret"}
              </button>
            </form>
          </>
        )}
        <ErrorBox error={error} />
        <div className="auth-foot">
          <ShieldCheck size={14} /> Значение секрета отсутствует в URL
        </div>
      </div>
    </div>
  );
}
