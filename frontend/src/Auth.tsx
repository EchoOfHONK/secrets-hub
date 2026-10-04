import { useState } from "react";
import {
  ShieldCheck,
  LockKeyhole,
  Download,
  Check,
  ArrowRight,
  KeyRound,
} from "lucide-react";
import { request, downloadText, setCsrf } from "./api";
import { Field, ErrorBox, submit, safeError, Modal } from "./ui";
import type { Session } from "./types";
function Brand() {
  return (
    <div className="auth-brand">
      <span className="brand-mark">
        <ShieldCheck size={27} />
      </span>
      <span>Secrets Hub</span>
    </div>
  );
}
export function Login({ onSession }: { onSession: (s: Session) => void }) {
  const [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [otp, setOtp] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [recover, setRecover] = useState(false),
    [recovery, setRecovery] = useState("");
  async function login() {
    setBusy(true);
    setError("");
    try {
      if (recover) {
        await request("/auth/recover", {
          username,
          recovery_key: recovery,
          new_password: password,
        });
        const refreshed = await request<Session>("/auth/session");
        setCsrf(refreshed.csrf_token);
        setRecover(false);
        setRecovery("");
        setPassword("");
        setError("Пароль изменён. Войдите с новым паролем.");
      } else {
        const s = await request<Session>("/auth/login", {
          username,
          password,
          otp: otp || undefined,
        });
        setCsrf(s.csrf_token);
        onSession(s);
      }
    } catch (e) {
      setError(safeError(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="auth-layout">
      <div className="auth-card">
        <Brand />
        <div className="auth-emblem">
          <LockKeyhole size={36} />
        </div>
        <h1>
          {recover ? "Восстановление доступа" : "Ваши секреты. Под защитой."}
        </h1>
        <p>
          {recover
            ? "Нужен recovery key из комплекта восстановления."
            : "Войдите в своё защищённое хранилище."}
        </p>
        <form onSubmit={submit(login)}>
          <Field label="Имя пользователя">
            <input
              required
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </Field>
          <Field
            label={recover ? "Новый пароль (минимум 12 символов)" : "Пароль"}
          >
            <input
              type="password"
              required
              minLength={recover ? 12 : undefined}
              autoComplete={recover ? "new-password" : "current-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
          {recover ? (
            <Field label="Recovery key">
              <textarea
                required
                value={recovery}
                onChange={(e) => setRecovery(e.target.value)}
                autoComplete="off"
              />
            </Field>
          ) : (
            <Field
              label="Код 2FA или recovery code"
              hint="Оставьте пустым, если 2FA не включена."
            >
              <input
                autoComplete="one-time-code"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
              />
            </Field>
          )}
          <ErrorBox error={error} />
          <button disabled={busy} className="button primary full">
            {busy
              ? "Проверка…"
              : recover
                ? "Восстановить доступ"
                : "Открыть хранилище"}
            <ArrowRight size={17} />
          </button>
        </form>
        <button
          className="text-button"
          onClick={() => {
            setRecover(!recover);
            setError("");
            setPassword("");
          }}
        >
          {recover ? "Вернуться к входу" : "Не помню пароль"}
        </button>
        <div className="auth-foot">
          <ShieldCheck size={14} /> Self-hosted · Encrypted at rest
        </div>
      </div>
    </div>
  );
}
const steps = [
  "Welcome",
  "Администратор",
  "Шифрование",
  "Безопасность",
  "Название",
  "Адрес приложения",
  "Recovery kit",
  "Готово",
];
export function Setup({
  initial,
  onSession,
}: {
  initial: Session;
  onSession: (s: Session) => void;
}) {
  const [step, setStep] = useState(0),
    [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [confirm, setConfirm] = useState(""),
    [master, setMaster] = useState(""),
    [name, setName] = useState("Secrets Hub"),
    [url, setUrl] = useState(location.origin),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [result, setResult] = useState<
      (Session & { recovery_key: string; recovery_kit: unknown }) | null
    >(null),
    [saved, setSaved] = useState(false);
  async function next() {
    setError("");
    if (
      step === 1 &&
      (password.length < 12 || password !== confirm || !username.trim())
    ) {
      setError("Укажите имя и совпадающие пароли длиной от 12 символов.");
      return;
    }
    if (step === 2 && master.length < 16) {
      setError("Используйте мастер-пароль длиной от 16 символов.");
      return;
    }
    if (step === 5) {
      try {
        const parsed = new URL(url);
        if (
          !["http:", "https:"].includes(parsed.protocol) ||
          parsed.pathname !== "/" ||
          parsed.search ||
          parsed.hash
        ) {
          setError(
            "Укажите адрес без пути, например https://secrets.example.org",
          );
          return;
        }
      } catch {
        setError("Укажите корректный URL");
        return;
      }
      setBusy(true);
      try {
        const r = await request<
          Session & { recovery_key: string; recovery_kit: unknown }
        >("/setup", {
          username,
          password,
          master_password: master,
          instance_name: name,
          app_url: url,
        });
        setResult(r);
        setCsrf(r.csrf_token);
        setPassword("");
        setConfirm("");
        setMaster("");
        setStep(6);
      } catch (e) {
        setError(safeError(e));
      } finally {
        setBusy(false);
      }
      return;
    }
    setStep(step + 1);
  }
  return (
    <div className="setup-layout">
      <aside className="setup-sidebar">
        <Brand />
        <h2>
          Ваше личное
          <br />
          хранилище секретов
        </h2>
        <p>Ключи, пароли и конфигурации в одном месте на вашем сервере.</p>
        <ol>
          {steps.map((s, i) => (
            <li
              className={i === step ? "active" : i < step ? "done" : ""}
              key={s}
            >
              <span>{i < step ? <Check size={15} /> : i + 1}</span>
              {s}
            </li>
          ))}
        </ol>
        <div className="auth-foot">
          <ShieldCheck size={16} /> Без стандартных паролей
        </div>
      </aside>
      <main className="setup-main">
        <div className="setup-content">
          <span className="eyebrow">FIRST RUN · {step + 1} / 8</span>
          <h1>{steps[step]}</h1>
          <form onSubmit={submit(next)}>
            {step === 0 && (
              <>
                <p className="lead">Добро пожаловать в Secrets Hub.</p>
                <p>
                  Настроим администратора, шифрование и восстановление доступа.
                  Установка занимает несколько минут.
                </p>
                <div className="info-card">
                  <ShieldCheck />
                  <div>
                    <strong>Вы управляете своими данными</strong>
                    <p>
                      Все значения секретов шифруются до записи в базу.
                      Мастер-ключ хранится отдельно на сервере.
                    </p>
                  </div>
                </div>
              </>
            )}
            {step === 1 && (
              <>
                <p>Этот пользователь будет управлять хранилищем и доступом.</p>
                <Field label="Имя пользователя">
                  <input
                    required
                    autoComplete="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </Field>
                <Field label="Пароль">
                  <input
                    required
                    type="password"
                    minLength={12}
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </Field>
                <Field label="Повторите пароль">
                  <input
                    required
                    type="password"
                    autoComplete="new-password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                  />
                </Field>
              </>
            )}
            {step === 2 && (
              <>
                <p>
                  Мастер-пароль защищает резервную обёртку ключа шифрования.
                  Сохраните его отдельно от сервера.
                </p>
                <Field
                  label="Мастер-пароль"
                  hint="Минимум 16 символов. Не используйте пароль администратора."
                >
                  <input
                    required
                    minLength={16}
                    type="password"
                    autoComplete="new-password"
                    value={master}
                    onChange={(e) => setMaster(e.target.value)}
                  />
                </Field>
                <div className="info-card">
                  <KeyRound />
                  <p>
                    Сервер расшифровывает секреты после проверки прав. Это
                    серверное шифрование, поэтому доступ к серверу и
                    мастер-ключу нужно защищать.
                  </p>
                </div>
              </>
            )}
            {step === 3 && (
              <>
                <p>Перед началом работы проверьте соединение.</p>
                <div className="check-row">
                  <Check /> Шифрование AES-256-GCM
                </div>
                <div className="check-row">
                  <Check /> Argon2id для паролей
                </div>
                <div className="check-row">
                  <Check /> Нет стандартных учётных записей
                </div>
                <div className="check-row">
                  {window.isSecureContext ? <Check /> : <LockKeyhole />}
                  {location.protocol === "https:"
                    ? " HTTPS используется"
                    : window.isSecureContext
                      ? " Localhost: безопасный контекст браузера"
                      : " HTTP: настройте HTTPS перед хранением секретов"}
                </div>
                <p className="muted">
                  Для LAN и публичного домена используйте HTTPS через nginx.
                  HTTP передаёт данные без защиты.
                </p>
              </>
            )}
            {step === 4 && (
              <>
                <p>Название будет видно в боковом меню.</p>
                <Field label="Название инстанса">
                  <input
                    required
                    maxLength={80}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </Field>
              </>
            )}
            {step === 5 && (
              <>
                <p>
                  Укажите адрес, по которому будете открывать приложение. Он
                  используется для проверки источника запросов и временных
                  ссылок.
                </p>
                <Field label="URL приложения">
                  <input
                    required
                    type="url"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                  />
                </Field>
                <p className="muted">
                  HTTPS за proxy задаётся в installer. Для смены домена обновите
                  APP_URL и настройку адреса.
                </p>
              </>
            )}
            {step === 6 && result && (
              <>
                <p>
                  Скачайте recovery kit и сохраните офлайн. Ключ позволяет
                  восстановить шифрование и сбросить пароль администратора.
                </p>
                <div className="warning-box">
                  Любой обладатель recovery key получает возможность
                  восстановить доступ. Храните его отдельно от сервера и
                  резервных копий.
                </div>
                <Field label="Recovery key">
                  <textarea
                    readOnly
                    className="mono"
                    value={result.recovery_key}
                  />
                </Field>
                <button
                  type="button"
                  className="button"
                  onClick={() => {
                    downloadText(
                      typeof result.recovery_kit === "string"
                        ? result.recovery_kit
                        : JSON.stringify(result.recovery_kit, null, 2),
                      "secrets-hub-recovery-kit.json",
                      "application/json",
                    );
                    setSaved(true);
                  }}
                >
                  <Download size={17} /> Скачать recovery kit
                </button>
                <label className="checkbox">
                  <input
                    type="checkbox"
                    checked={saved}
                    onChange={(e) => setSaved(e.target.checked)}
                  />{" "}
                  Я сохранил комплект восстановления в безопасном месте
                </label>
              </>
            )}
            {step === 7 && (
              <>
                <div className="success-emblem">
                  <ShieldCheck size={48} />
                </div>
                <p className="lead">Хранилище готово.</p>
                <p>
                  Начните с первого секрета или импортируйте существующие
                  конфигурации. Включите 2FA в Settings → Authentication.
                </p>
              </>
            )}
            <ErrorBox error={error} />
            <div className="form-actions">
              {step > 0 && step < 6 && (
                <button
                  type="button"
                  className="button"
                  onClick={() => setStep(step - 1)}
                >
                  Назад
                </button>
              )}
              {step === 7 ? (
                <button
                  type="button"
                  className="button primary"
                  onClick={() => result && onSession(result)}
                >
                  Открыть Secrets Hub
                </button>
              ) : (
                <button
                  disabled={busy || (step === 6 && !saved)}
                  className="button primary"
                >
                  {busy
                    ? "Создание хранилища…"
                    : step === 5
                      ? "Создать хранилище"
                      : "Продолжить"}
                  <ArrowRight size={16} />
                </button>
              )}
            </div>
          </form>
          <span className="muted">
            {initial.setup_required
              ? "Первичная настройка"
              : "Настройка завершена"}
          </span>
        </div>
      </main>
    </div>
  );
}
export function LockScreen({ onUnlock }: { onUnlock: () => void }) {
  const [password, setPassword] = useState(""),
    [otp, setOtp] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  return (
    <div className="lock-screen">
      <div className="auth-card">
        <Brand />
        <div className="auth-emblem">
          <LockKeyhole size={40} />
        </div>
        <h1>Secrets Hub Locked</h1>
        <p>Секреты скрыты. Введите пароль для продолжения.</p>
        <form
          onSubmit={submit(async () => {
            setBusy(true);
            try {
              await request("/auth/unlock", {
                password,
                otp: otp || undefined,
              });
              onUnlock();
            } catch (e) {
              setError(safeError(e));
            } finally {
              setBusy(false);
            }
          })}
        >
          <Field label="Пароль">
            <input
              required
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
          <Field label="Код 2FA (если включена)">
            <input
              autoComplete="one-time-code"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
            />
          </Field>
          <ErrorBox error={error} />
          <button className="button primary full" disabled={busy}>
            Unlock
          </button>
        </form>
      </div>
    </div>
  );
}
export function Reauth({
  onClose,
  onSuccess,
}: {
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [password, setPassword] = useState(""),
    [otp, setOtp] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  return (
    <Modal title="Подтвердите личность" onClose={onClose}>
      <p>Для этого действия нужна повторная проверка пароля и 2FA.</p>
      <form
        onSubmit={submit(async () => {
          setBusy(true);
          try {
            await request("/auth/reauth", { password, otp: otp || undefined });
            onSuccess();
          } catch (e) {
            setError(safeError(e));
          } finally {
            setBusy(false);
          }
        })}
      >
        <Field label="Пароль">
          <input
            autoFocus
            required
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
        <Field label="Код 2FA или recovery code">
          <input
            autoComplete="one-time-code"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
          />
        </Field>
        <ErrorBox error={error} />
        <div className="form-actions">
          <button disabled={busy} className="button primary">
            Подтвердить
          </button>
        </div>
      </form>
    </Modal>
  );
}
