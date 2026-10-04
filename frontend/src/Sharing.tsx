import { useEffect, useState } from "react";
import { Link, Copy, Trash2, UserPlus, ShieldCheck } from "lucide-react";
import { request, copyText } from "./api";
import {
  Modal,
  Field,
  ErrorBox,
  Loading,
  submit,
  safeError,
  DateText,
} from "./ui";
import type { Permission, User, TemporaryLink, Secret } from "./types";
export function AccessDialog({
  id,
  kind,
  onClose,
  notify,
}: {
  id: string;
  kind: "secret" | "collection";
  onClose: () => void;
  notify: (m: string) => void;
}) {
  const [users, setUsers] = useState<User[]>([]),
    [grants, setGrants] = useState<Permission[]>([]),
    [userId, setUserId] = useState(""),
    [access, setAccess] = useState<"read" | "write" | "none">("read"),
    [canCopy, setCanCopy] = useState(true),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true);
  const path =
    kind === "secret"
      ? `/secrets/${id}/shares`
      : `/collections/${id}/permissions`;
  async function load() {
    try {
      const [u, g] = await Promise.all([
        request<User[]>("/users"),
        request<Permission[]>(path),
      ]);
      setUsers(u);
      setGrants(g);
    } catch (e) {
      setError(safeError(e));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, [id]);
  async function change(next: Permission[]) {
    await request(
      path,
      kind === "collection" ? next : next.at(-1),
      kind === "collection" ? "PUT" : "POST",
    );
    await load();
    notify("Права доступа обновлены");
  }
  return (
    <Modal
      title={kind === "secret" ? "Поделиться секретом" : "Доступ к collection"}
      onClose={onClose}
    >
      {loading ? (
        <Loading />
      ) : (
        <>
          <p className="muted">
            Admin имеет доступ ко всему хранилищу. Viewer не может
            редактировать, даже с разрешением Write.
          </p>
          {grants.map((g) => (
            <div className="grant" key={g.user_id}>
              <div>
                <strong>
                  {users.find((u) => u.id === g.user_id)?.username || g.user_id}
                </strong>
                <span className="muted">
                  {g.access} · Copy {g.can_copy ? "allowed" : "forbidden"}
                </span>
              </div>
              <button
                className="icon-button"
                aria-label="Удалить разрешение"
                onClick={async () => {
                  try {
                    if (kind === "secret")
                      await request(`${path}/${g.user_id}`, {}, "DELETE");
                    else
                      await request(
                        path,
                        grants.filter((x) => x.user_id !== g.user_id),
                        "PUT",
                      );
                    await load();
                    notify("Разрешение удалено");
                  } catch (e) {
                    setError(safeError(e));
                  }
                }}
              >
                <Trash2 size={16} />
              </button>
            </div>
          ))}
          <form
            onSubmit={submit(async () => {
              try {
                const g: Permission = {
                  user_id: userId,
                  access,
                  can_copy: canCopy,
                };
                await change([
                  ...grants.filter((x) => x.user_id !== userId),
                  g,
                ]);
                setUserId("");
                setError("");
              } catch (e) {
                setError(safeError(e));
              }
            })}
          >
            <Field label="Пользователь">
              <select
                required
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
              >
                <option value="">Выберите пользователя</option>
                {users
                  .filter((u) => !u.disabled && u.role !== "admin")
                  .map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.username}
                    </option>
                  ))}
              </select>
            </Field>
            <Field label="Доступ">
              <select
                value={access}
                onChange={(e) => setAccess(e.target.value as typeof access)}
              >
                <option value="read">View</option>
                <option value="write">Edit</option>
                {kind === "collection" && (
                  <option value="none">No Access</option>
                )}
              </select>
            </Field>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={canCopy}
                onChange={(e) => setCanCopy(e.target.checked)}
              />{" "}
              Copy allowed
            </label>
            <p className="muted">
              Запрет Copy отключает копирование и экспорт в приложении. Видимый
              текст можно переписать или сфотографировать.
            </p>
            <ErrorBox error={error} />
            <button className="button primary" disabled={!userId}>
              <UserPlus size={16} /> Сохранить доступ
            </button>
          </form>
        </>
      )}
    </Modal>
  );
}
export function TemporaryDialog({
  secret,
  onClose,
  onSaved,
  notify,
}: {
  secret: Secret;
  onClose: () => void;
  onSaved: () => void;
  notify: (m: string) => void;
}) {
  const [minutes, setMinutes] = useState("60"),
    [custom, setCustom] = useState(120),
    [max, setMax] = useState(1),
    [password, setPassword] = useState(""),
    [allowCopy, setAllowCopy] = useState(true),
    [url, setUrl] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  return (
    <Modal title="Temporary Access" onClose={onClose}>
      {url ? (
        <>
          <div className="info-card">
            <ShieldCheck />
            <p>
              Ссылка создана. Она показывается один раз. Отправьте её получателю
              безопасным способом.
            </p>
          </div>
          <Field label="Ссылка">
            <textarea className="mono" readOnly value={url} />
          </Field>
          <button
            className="button primary"
            onClick={async () => {
              try {
                await copyText(url);
                notify("Ссылка скопирована в clipboard");
              } catch (e) {
                setError(safeError(e));
              }
            }}
          >
            <Copy size={16} /> Copy link
          </button>
          <ErrorBox error={error} />
        </>
      ) : (
        <form
          onSubmit={submit(async () => {
            setBusy(true);
            try {
              const r = await request<{ url: string; token: string }>(
                "/temporary-links",
                {
                  secret_id: secret.id,
                  expires_minutes:
                    minutes === "custom" ? custom : Number(minutes),
                  max_views: max,
                  password: password || undefined,
                  allow_copy: allowCopy,
                },
              );
              setUrl(r.url);
              setPassword("");
              onSaved();
            } catch (e) {
              setError(safeError(e));
            } finally {
              setBusy(false);
            }
          })}
        >
          <p>
            Временный доступ к <strong>{secret.name}</strong>.
          </p>
          <Field label="Expiration">
            <select
              value={minutes}
              onChange={(e) => setMinutes(e.target.value)}
            >
              <option value="5">5 minutes</option>
              <option value="30">30 minutes</option>
              <option value="60">1 hour</option>
              <option value="1440">24 hours</option>
              <option value="custom">Custom</option>
            </select>
          </Field>
          {minutes === "custom" && (
            <Field label="Минуты">
              <input
                type="number"
                required
                min={1}
                max={43200}
                value={custom}
                onChange={(e) => setCustom(Number(e.target.value))}
              />
            </Field>
          )}
          <Field
            label="Максимальное количество просмотров"
            hint="1 — одноразовый доступ."
          >
            <input
              type="number"
              required
              min={1}
              max={1000}
              value={max}
              onChange={(e) => setMax(Number(e.target.value))}
            />
          </Field>
          <Field label="Пароль ссылки (необязательно)">
            <input
              autoComplete="new-password"
              type="password"
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={allowCopy}
              onChange={(e) => setAllowCopy(e.target.checked)}
            />{" "}
            Copy allowed
          </label>
          <p className="muted">
            При запрете Copy кнопка скрывается. Браузер не может запретить
            переписывание, скриншот или инструменты разработчика.
          </p>
          <ErrorBox error={error} />
          <button disabled={busy} className="button primary">
            <Link size={16} />
            {busy ? "Создание…" : "Создать временную ссылку"}
          </button>
        </form>
      )}
    </Modal>
  );
}
export function TemporaryPage({ notify }: { notify: (m: string) => void }) {
  const [items, setItems] = useState<TemporaryLink[]>([]),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true);
  async function load() {
    try {
      setItems(await request("/temporary-links"));
    } catch (e) {
      setError(safeError(e));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, []);
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">CONTROLLED SHARING</span>
          <h1>Temporary Access</h1>
          <p>Временные ссылки с ограничением срока и просмотров.</p>
        </div>
      </div>
      <ErrorBox error={error} />
      {loading ? (
        <Loading />
      ) : (
        <div className="panel table-wrap">
          <table>
            <thead>
              <tr>
                <th>Secret</th>
                <th>Expires</th>
                <th>Views</th>
                <th>Copy</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((link) => (
                <tr key={link.id}>
                  <td>
                    <strong>
                      {link.secret_name || link.name || link.secret_id}
                    </strong>
                  </td>
                  <td>
                    <DateText value={link.expires_at} />
                  </td>
                  <td>
                    {link.views} / {link.max_views}
                  </td>
                  <td>{link.allow_copy ? "Allowed" : "Forbidden"}</td>
                  <td>
                    <span
                      className={
                        "badge " +
                        (link.revoked ||
                        new Date(link.expires_at).getTime() < Date.now() ||
                        link.views >= link.max_views
                          ? ""
                          : "success")
                      }
                    >
                      {link.revoked
                        ? "Revoked"
                        : new Date(link.expires_at).getTime() < Date.now()
                          ? "Expired"
                          : link.views >= link.max_views
                            ? "Consumed"
                            : "Active"}
                    </span>
                  </td>
                  <td>
                    <button
                      className="button small"
                      disabled={link.revoked}
                      onClick={async () => {
                        if (!confirm("Отозвать ссылку?")) return;
                        try {
                          await request(
                            "/temporary-links/" + link.id,
                            {},
                            "DELETE",
                          );
                          await load();
                          notify("Ссылка отозвана");
                        } catch (e) {
                          setError(safeError(e));
                        }
                      }}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!items.length && (
            <div className="empty">
              <Link size={32} />
              <h3>Активных ссылок нет</h3>
              <p>Откройте секрет и выберите Temporary Access.</p>
            </div>
          )}
        </div>
      )}
    </>
  );
}
