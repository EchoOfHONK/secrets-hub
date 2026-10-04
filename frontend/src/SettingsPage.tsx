import { useEffect, useState } from "react";
import {
  ShieldCheck,
  KeyRound,
  Download,
  Upload,
  LockKeyhole,
  Check,
  Save,
  Database,
  LogOut,
} from "lucide-react";
import { request, downloadApi, downloadText, fileBase64 } from "./api";
import {
  Loading,
  ErrorBox,
  Field,
  Modal,
  DateText,
  submit,
  safeError,
} from "./ui";
import type { Settings, Security, Backup, Session, Page } from "./types";
const tabs = [
  "General",
  "Security",
  "Users",
  "Authentication",
  "Encryption",
  "Backups",
  "Appearance",
  "Session",
  "Audit",
  "Advanced",
];
export function SettingsPage({
  session,
  onSession,
  notify,
  reauth,
  onNavigate,
}: {
  session: Session;
  onSession: (s: Session) => void;
  notify: (s: string) => void;
  reauth: (action: () => Promise<void>) => void;
  onNavigate: (p: Page) => void;
}) {
  const [tab, setTab] = useState("Security"),
    [settings, setSettings] = useState<Settings | null>(null),
    [security, setSecurity] = useState<Security | null>(null),
    [backups, setBackups] = useState<Backup[]>([]),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [backupPassword, setBackupPassword] = useState(""),
    [restoreFile, setRestoreFile] = useState<File | null>(null),
    [restorePassword, setRestorePassword] = useState(""),
    [totp, setTotp] = useState<{
      secret: string;
      uri: string;
      qr_data_url: string;
    } | null>(null),
    [code, setCode] = useState(""),
    [codes, setCodes] = useState<string[] | null>(null),
    [oldPassword, setOldPassword] = useState(""),
    [newPassword, setNewPassword] = useState(""),
    [otp, setOtp] = useState(""),
    [disablePassword, setDisablePassword] = useState(""),
    [disableCode, setDisableCode] = useState(""),
    [compact, setCompact] = useState(
      localStorage.getItem("sh-compact") === "true",
    ),
    [motion, setMotion] = useState(
      localStorage.getItem("sh-reduce-motion") === "true",
    );
  const admin = session.user?.role === "admin";
  async function load() {
    try {
      const [s, c] = await Promise.all([
        request<Settings>("/settings"),
        request<Security>("/security"),
      ]);
      setSettings(s);
      setSecurity(c);
      if (admin) setBackups(await request("/backups"));
    } catch (e) {
      setError(safeError(e));
    }
  }
  useEffect(() => {
    void load();
  }, []);
  async function save() {
    if (!settings) return;
    reauth(async () => {
      setBusy(true);
      try {
        await request("/settings", settings, "PUT");
        await refreshSession();
        notify("Настройки сохранены");
        setError("");
        await load();
      } catch (e) {
        setError(safeError(e));
      } finally {
        setBusy(false);
      }
    });
  }
  async function refreshSession() {
    const s = await request<Session>("/auth/session");
    onSession(s);
  }
  const set = <K extends keyof Settings>(key: K, value: Settings[K]) => {
    if (settings) setSettings({ ...settings, [key]: value });
  };
  async function action(fn: () => Promise<void>) {
    setError("");
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      setError(safeError(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">MAKE IT YOURS</span>
          <h1>Settings</h1>
          <p>Безопасность, восстановление и настройки хранилища.</p>
        </div>
        <span className="badge">
          <ShieldCheck size={14} /> Self-hosted
        </span>
      </div>
      <div className="settings-layout">
        <nav className="settings-nav">
          {tabs.map((t) => (
            <button
              key={t}
              className={tab === t ? "active" : ""}
              onClick={() => {
                setError("");
                if (t === "Users") onNavigate("users");
                else if (t === "Audit") onNavigate("audit");
                else setTab(t);
              }}
              disabled={
                !admin &&
                [
                  "Users",
                  "Backups",
                  "Advanced",
                  "General",
                  "Encryption",
                ].includes(t)
              }
            >
              {t}
            </button>
          ))}
        </nav>
        <div className="settings-content">
          <ErrorBox error={error} />
          {!settings || !security ? (
            <Loading />
          ) : (
            <>
              {tab === "Security" && (
                <>
                  <div className="section-title">
                    <h2>Security Center</h2>
                    <p>Проверка защиты без массовой расшифровки секретов.</p>
                  </div>
                  <div className="security-grid">
                    {[
                      {
                        title: "Encryption",
                        value: security.encryption ? "Enabled" : "Disabled",
                        ok: security.encryption,
                        desc: "AES-256-GCM at rest",
                      },
                      {
                        title: "HTTPS",
                        value: security.https ? "Detected" : "HTTP",
                        ok: security.https,
                        desc: "Соединение с сервером",
                      },
                      {
                        title: "Master Key",
                        value: security.master_key ? "Configured" : "Missing",
                        ok: security.master_key,
                        desc: "Отдельно от базы данных",
                      },
                      {
                        title: "2FA",
                        value: security.totp_enabled ? "Enabled" : "Disabled",
                        ok: security.totp_enabled,
                        desc: "Ваша учётная запись",
                      },
                    ].map((s) => (
                      <div className="panel security-card" key={s.title}>
                        <span className="muted">{s.title}</span>
                        <strong
                          className={s.ok ? "success-text" : "warning-text"}
                        >
                          {s.ok ? (
                            <ShieldCheck size={18} />
                          ) : (
                            <LockKeyhole size={18} />
                          )}
                          {s.value}
                        </strong>
                        <small>{s.desc}</small>
                      </div>
                    ))}
                  </div>
                  <section className="panel">
                    <div className="overview-row">
                      <span>Last backup</span>
                      <DateText value={security.last_backup} />
                    </div>
                    <div className="overview-row">
                      <span>Failed logins · 24h</span>
                      <strong>{security.failed_logins}</strong>
                    </div>
                    <div className="overview-row">
                      <span>Weak passwords</span>
                      <strong>{security.weak_passwords}</strong>
                    </div>
                    <div className="overview-row">
                      <span>Expired secrets</span>
                      <strong>{security.expired_secrets}</strong>
                    </div>
                  </section>
                  <p className="muted">
                    Слабые пароли оцениваются при записи. HTTPS определяется по
                    соединению, включая доверенный proxy.
                  </p>
                </>
              )}
              {tab === "General" && (
                <section className="panel settings-panel">
                  <h2>General</h2>
                  <form onSubmit={submit(save)}>
                    <Field label="Instance name">
                      <input
                        required
                        value={settings.instance_name}
                        onChange={(e) => set("instance_name", e.target.value)}
                      />
                    </Field>
                    <Field
                      label="Application URL"
                      hint="Origin без пути. После смены адреса обновите APP_URL на сервере и войдите снова."
                    >
                      <input
                        required
                        type="url"
                        value={settings.app_url}
                        onChange={(e) => set("app_url", e.target.value)}
                      />
                    </Field>
                    <button disabled={busy} className="button primary">
                      <Save size={16} /> Сохранить
                    </button>
                  </form>
                </section>
              )}
              {tab === "Authentication" && (
                <>
                  <section className="panel settings-panel">
                    <h2>Two-factor authentication</h2>
                    <p>
                      Google Authenticator, Aegis, Authy и другие
                      TOTP-приложения.
                    </p>
                    {security.totp_enabled ? (
                      <>
                        <span className="badge success">
                          <Check size={14} /> 2FA Enabled
                        </span>
                        <p className="muted">
                          После восстановления backup создайте новые recovery
                          codes. Старые коды отменяются при восстановлении.
                        </p>
                        <button
                          className="button"
                          disabled={busy}
                          onClick={() =>
                            reauth(() =>
                              action(async () => {
                                const result = await request<{
                                  recovery_codes: string[];
                                }>("/auth/totp/recovery-codes", {});
                                setCodes(result.recovery_codes);
                                notify(
                                  "Созданы новые recovery codes. Старые коды отменены.",
                                );
                              }),
                            )
                          }
                        >
                          Создать новые recovery codes
                        </button>
                        <form
                          onSubmit={submit(() =>
                            action(async () => {
                              await request("/auth/totp/disable", {
                                password: disablePassword,
                                code: disableCode,
                              });
                              setDisablePassword("");
                              setDisableCode("");
                              await refreshSession();
                              await load();
                              notify("2FA отключена");
                            }),
                          )}
                        >
                          <Field label="Пароль для отключения">
                            <input
                              type="password"
                              required
                              autoComplete="current-password"
                              value={disablePassword}
                              onChange={(e) =>
                                setDisablePassword(e.target.value)
                              }
                            />
                          </Field>
                          <Field label="Код 2FA или recovery code">
                            <input
                              required
                              autoComplete="one-time-code"
                              value={disableCode}
                              onChange={(e) => setDisableCode(e.target.value)}
                            />
                          </Field>
                          <button disabled={busy} className="button">
                            Disable 2FA
                          </button>
                        </form>
                      </>
                    ) : (
                      <>
                        <p className="warning-text">
                          2FA ещё не включена для вашей учётной записи.
                        </p>
                        <button
                          disabled={busy}
                          className="button primary"
                          onClick={() =>
                            reauth(() =>
                              action(async () => {
                                setTotp(await request("/auth/totp/setup", {}));
                                setCode("");
                              }),
                            )
                          }
                        >
                          <ShieldCheck size={16} /> Enable 2FA
                        </button>
                      </>
                    )}
                  </section>
                  <section className="panel settings-panel">
                    <h2>Изменить пароль</h2>
                    <form
                      onSubmit={submit(() =>
                        action(async () => {
                          await request("/auth/password", {
                            old_password: oldPassword,
                            new_password: newPassword,
                            otp: otp || undefined,
                          });
                          setOldPassword("");
                          setNewPassword("");
                          setOtp("");
                          notify("Пароль обновлён. Другие сессии завершены.");
                        }),
                      )}
                    >
                      <Field label="Текущий пароль">
                        <input
                          type="password"
                          required
                          autoComplete="current-password"
                          value={oldPassword}
                          onChange={(e) => setOldPassword(e.target.value)}
                        />
                      </Field>
                      <Field label="Новый пароль">
                        <input
                          type="password"
                          required
                          minLength={12}
                          autoComplete="new-password"
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                        />
                      </Field>
                      <Field label="Код 2FA или recovery code">
                        <input
                          autoComplete="one-time-code"
                          value={otp}
                          onChange={(e) => setOtp(e.target.value)}
                        />
                      </Field>
                      <button disabled={busy} className="button">
                        Изменить пароль
                      </button>
                    </form>
                  </section>
                </>
              )}
              {tab === "Encryption" && (
                <section className="panel settings-panel">
                  <div className="info-card">
                    <KeyRound />
                    <div>
                      <h2>Encryption enabled</h2>
                      <p>
                        AES-256-GCM через библиотеку cryptography. Каждый объект
                        получает новый nonce и привязку к своему идентификатору.
                      </p>
                    </div>
                  </div>
                  <div className="overview-row">
                    <span>Master key</span>
                    <strong>
                      {security.master_key ? "Configured" : "Missing"}
                    </strong>
                  </div>
                  <p>
                    Мастер-ключ хранится в защищённом файле на сервере.
                    Мастер-пароль и recovery key защищают его резервные обёртки.
                    Их нельзя заменить без исходного ключа.
                  </p>
                  <p>
                    Комплект восстановления создан при установке. Сохраните его
                    отдельно от сервера. В разделе Backups можно создать
                    переносимую копию с отдельным паролем.
                  </p>
                  <button className="button" onClick={() => setTab("Backups")}>
                    <Database size={16} /> Открыть Backups
                  </button>
                </section>
              )}
              {tab === "Backups" && (
                <>
                  <section className="panel settings-panel">
                    <h2>Manual encrypted backup</h2>
                    <p>
                      Снимок базы, зашифрованных секретов, истории,
                      пользователей и настроек. Файл защищён отдельным паролем и
                      подходит для переноса на другой сервер.
                    </p>
                    <form
                      onSubmit={submit(async () => {
                        if (backupPassword.length < 12) {
                          setError(
                            "Пароль backup должен содержать минимум 12 символов",
                          );
                          return;
                        }
                        reauth(() =>
                          action(async () => {
                            const b = await request<Backup>("/backups", {
                              password: backupPassword,
                            });
                            setBackupPassword("");
                            await load();
                            await downloadApi(
                              "/backups/" + b.id + "/download",
                              {},
                              b.filename,
                            );
                            notify("Encrypted backup создан и скачан");
                          }),
                        );
                      })}
                    >
                      <Field label="Пароль резервной копии">
                        <input
                          required
                          type="password"
                          minLength={12}
                          autoComplete="new-password"
                          value={backupPassword}
                          onChange={(e) => setBackupPassword(e.target.value)}
                        />
                      </Field>
                      <button disabled={busy} className="button primary">
                        <Download size={16} /> Create backup
                      </button>
                    </form>
                  </section>
                  <section className="panel settings-panel">
                    <h2>Scheduled backups</h2>
                    <form onSubmit={submit(save)}>
                      <label className="checkbox">
                        <input
                          type="checkbox"
                          checked={settings.backup_enabled}
                          onChange={(e) =>
                            set("backup_enabled", e.target.checked)
                          }
                        />{" "}
                        Ежедневное резервное копирование
                      </label>
                      <Field label="Час запуска (UTC)">
                        <input
                          type="number"
                          min={0}
                          max={23}
                          value={settings.backup_hour}
                          onChange={(e) =>
                            set("backup_hour", Number(e.target.value))
                          }
                        />
                      </Field>
                      <div className="form-grid three">
                        {(
                          [
                            "retention_daily",
                            "retention_weekly",
                            "retention_monthly",
                          ] as const
                        ).map((k, i) => (
                          <Field
                            key={k}
                            label={["Daily", "Weekly", "Monthly"][i]}
                          >
                            <input
                              type="number"
                              min={i ? 0 : 1}
                              max={[365, 52, 60][i]}
                              value={settings[k]}
                              onChange={(e) => set(k, Number(e.target.value))}
                            />
                          </Field>
                        ))}
                      </div>
                      <p className="muted">
                        Плановые копии защищены ключом этого сервера. Для
                        восстановления нужен исходный master.key. Периодически
                        скачивайте переносимую копию с паролем.
                      </p>
                      <button disabled={busy} className="button">
                        <Save size={16} /> Сохранить расписание
                      </button>
                    </form>
                  </section>
                  <section className="panel settings-panel">
                    <h2>Backup files</h2>
                    {backups.length ? (
                      backups.map((b) => (
                        <div className="backup-row" key={b.id}>
                          <div>
                            <strong>{b.filename}</strong>
                            <span>
                              <DateText value={b.created_at} />
                            </span>
                          </div>
                          <button
                            className="icon-button"
                            aria-label="Download backup"
                            onClick={() =>
                              reauth(() =>
                                action(async () => {
                                  await downloadApi(
                                    "/backups/" + b.id + "/download",
                                    {},
                                    b.filename,
                                  );
                                }),
                              )
                            }
                          >
                            <Download size={18} />
                          </button>
                        </div>
                      ))
                    ) : (
                      <p className="muted">Резервных копий ещё нет.</p>
                    )}
                  </section>
                  <section className="panel settings-panel">
                    <h2>Restore backup</h2>
                    <div className="warning-box">
                      Восстановление полностью заменит текущее хранилище и
                      завершит все сессии. Сначала скачайте копию текущих
                      данных.
                    </div>
                    <form
                      onSubmit={submit(async () => {
                        if (!restoreFile) return;
                        if (
                          !confirm(
                            "Полностью заменить хранилище данными из backup?",
                          )
                        )
                          return;
                        reauth(() =>
                          action(async () => {
                            await request("/backups/restore", {
                              content_base64: await fileBase64(restoreFile),
                              password: restorePassword || undefined,
                            });
                            setRestorePassword("");
                            setRestoreFile(null);
                            notify("Backup восстановлен. Войдите снова.");
                            window.dispatchEvent(new Event("session-expired"));
                          }),
                        );
                      })}
                    >
                      <Field label="Encrypted backup (.shbak)">
                        <input
                          required
                          type="file"
                          accept=".shbak"
                          onChange={(e) => {
                            const f = e.target.files?.[0] || null;
                            if (f && f.size > 64 * 1024 * 1024) {
                              setError("Максимальный размер backup — 64 MiB");
                              setRestoreFile(null);
                            } else setRestoreFile(f);
                          }}
                        />
                      </Field>
                      <Field
                        label="Пароль backup"
                        hint="Для плановой копии оставьте пустым; нужен исходный ключ сервера."
                      >
                        <input
                          type="password"
                          autoComplete="off"
                          value={restorePassword}
                          onChange={(e) => setRestorePassword(e.target.value)}
                        />
                      </Field>
                      <button
                        disabled={busy || !restoreFile}
                        className="button danger"
                      >
                        <Upload size={16} /> Restore backup
                      </button>
                    </form>
                  </section>
                </>
              )}
              {tab === "Appearance" && (
                <section className="panel settings-panel">
                  <h2>Appearance</h2>
                  <p>
                    Настройки этого браузера. Значения секретов в браузере не
                    сохраняются.
                  </p>
                  <label className="checkbox">
                    <input
                      type="checkbox"
                      checked={compact}
                      onChange={(e) => {
                        setCompact(e.target.checked);
                        localStorage.setItem(
                          "sh-compact",
                          String(e.target.checked),
                        );
                        document.documentElement.classList.toggle(
                          "compact",
                          e.target.checked,
                        );
                      }}
                    />{" "}
                    Компактные таблицы
                  </label>
                  <label className="checkbox">
                    <input
                      type="checkbox"
                      checked={motion}
                      onChange={(e) => {
                        setMotion(e.target.checked);
                        localStorage.setItem(
                          "sh-reduce-motion",
                          String(e.target.checked),
                        );
                        document.documentElement.classList.toggle(
                          "reduce-motion",
                          e.target.checked,
                        );
                      }}
                    />{" "}
                    Уменьшить анимацию
                  </label>
                  <div className="theme-swatch">
                    <span />
                    <strong>Dark · Secrets Hub</strong>
                    <span className="badge success">Active</span>
                  </div>
                </section>
              )}
              {tab === "Session" && (
                <section className="panel settings-panel">
                  <h2>Session & Lock Screen</h2>
                  <form onSubmit={submit(save)}>
                    <Field label="Блокировка при бездействии">
                      <select
                        disabled={!admin}
                        value={settings.lock_timeout}
                        onChange={(e) =>
                          set("lock_timeout", Number(e.target.value))
                        }
                      >
                        {[1, 5, 15, 30, 0].map((v) => (
                          <option key={v} value={v}>
                            {v ? v + " min" : "Never"}
                          </option>
                        ))}
                      </select>
                    </Field>
                    <Field label="Срок сессии (часы)">
                      <input
                        disabled={!admin}
                        type="number"
                        min={1}
                        max={168}
                        value={settings.session_hours}
                        onChange={(e) =>
                          set("session_hours", Number(e.target.value))
                        }
                      />
                    </Field>
                    {admin && (
                      <button disabled={busy} className="button primary">
                        Сохранить
                      </button>
                    )}
                  </form>
                  <hr />
                  <p>Завершите все активные сессии, включая текущую.</p>
                  <button
                    className="button"
                    onClick={() =>
                      void action(async () => {
                        await request("/auth/logout", { all_devices: true });
                        window.dispatchEvent(new Event("session-expired"));
                      })
                    }
                  >
                    <LogOut size={16} /> Logout from all devices
                  </button>
                </section>
              )}
              {tab === "Advanced" && (
                <section className="panel settings-panel">
                  <h2>Export</h2>
                  <p>Экспорт учитывает права доступа и разрешение Copy.</p>
                  <button
                    className="button"
                    onClick={() =>
                      reauth(() =>
                        action(async () => {
                          await downloadApi(
                            "/export",
                            { format: "csv" },
                            "secrets-hub-metadata.csv",
                          );
                          notify("Метаданные экспортированы");
                        }),
                      )
                    }
                  >
                    <Download size={16} /> CSV metadata
                  </button>
                  <div className="warning-box">
                    Полный JSON содержит незашифрованные значения секретов.
                    Любой, у кого есть файл, сможет прочитать их. Удалите файл
                    после использования и не храните его в общих папках.
                  </div>
                  <button
                    className="button danger"
                    onClick={() => {
                      if (
                        confirm(
                          "Скачать все доступные секреты в plaintext JSON? Файл не будет зашифрован.",
                        )
                      )
                        reauth(() =>
                          action(async () => {
                            await downloadApi(
                              "/export",
                              { format: "json" },
                              "secrets-hub-plaintext.json",
                            );
                            notify(
                              "Plaintext JSON скачан. Действие записано в audit log.",
                            );
                          }),
                        );
                    }}
                  >
                    <Download size={16} /> Plaintext JSON export
                  </button>
                </section>
              )}
            </>
          )}
        </div>
      </div>
      {totp && (
        <Modal
          title="Подключить 2FA"
          onClose={() => {
            setTotp(null);
            setCode("");
          }}
        >
          <p>
            Отсканируйте QR-код в TOTP-приложении. Код и ключ показываются
            только во время настройки.
          </p>
          <img
            className="qr"
            src={totp.qr_data_url}
            alt="QR-код подключения TOTP"
          />
          <Field label="Ключ для ручного ввода">
            <input className="mono" readOnly value={totp.secret} />
          </Field>
          <form
            onSubmit={submit(() =>
              action(async () => {
                const r = await request<{ recovery_codes: string[] }>(
                  "/auth/totp/enable",
                  { code },
                );
                setTotp(null);
                setCode("");
                setCodes(r.recovery_codes);
                await refreshSession();
                await load();
              }),
            )}
          >
            <Field label="6-значный код">
              <input
                required
                inputMode="numeric"
                pattern="[0-9]{6}"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </Field>
            <ErrorBox error={error} />
            <button disabled={busy} className="button primary">
              Подтвердить
            </button>
          </form>
        </Modal>
      )}
      {codes && (
        <Modal title="2FA recovery codes" onClose={() => setCodes(null)}>
          <div className="warning-box">
            Сохраните эти коды офлайн. Каждый можно использовать только один
            раз. Повторно они не показываются.
          </div>
          <pre className="config-output">{codes.join("\n")}</pre>
          <button
            className="button primary"
            onClick={() =>
              downloadText(codes.join("\n"), "secrets-hub-2fa-recovery.txt")
            }
          >
            <Download size={16} /> Скачать коды
          </button>
          <button className="button" onClick={() => setCodes(null)}>
            Я сохранил коды
          </button>
        </Modal>
      )}
    </>
  );
}
