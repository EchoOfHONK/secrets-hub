import { useEffect, useState } from "react";
import {
  KeyRound,
  Terminal,
  Network,
  Clock,
  ArrowUpRight,
  Folder,
  Server,
  Plus,
  ShieldCheck,
  Search,
  SlidersHorizontal,
  Upload,
  MoreHorizontal,
  Pencil,
  Trash2,
  Users,
  Activity as ActivityIcon,
} from "lucide-react";
import { request } from "./api";
import { actionLabel } from "./actions";
import {
  TypeIcon,
  DateText,
  Expiry,
  Loading,
  Empty,
  ErrorBox,
  ActivityList,
  Modal,
  Field,
  submit,
  safeError,
} from "./ui";
import {
  TYPES,
  type Secret,
  type Collection,
  type DashboardData,
  type Activity,
  type User,
} from "./types";
import { AccessDialog } from "./Sharing";
export function Dashboard({
  onOpen,
  onNew,
  canCreate,
}: {
  onOpen: (p: "secrets" | "ssh" | "wireguard") => void;
  onNew: () => void;
  canCreate: boolean;
}) {
  const [data, setData] = useState<DashboardData | null>(null),
    [error, setError] = useState("");
  useEffect(() => {
    request<DashboardData>("/dashboard")
      .then(setData)
      .catch((e) => setError(safeError(e)));
  }, []);
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">YOUR PRIVATE VAULT</span>
          <h1>Dashboard</h1>
          <p>Всё под контролем. Все секреты в одном месте.</p>
        </div>
        {canCreate && (
          <button className="button primary" onClick={onNew}>
            <Plus size={17} /> New Secret
          </button>
        )}
      </div>
      <ErrorBox error={error} />
      {!data ? (
        <Loading />
      ) : (
        <>
          <div className="stat-grid">
            {[
              {
                label: "Secrets",
                value: data.counts.secrets,
                Icon: KeyRound,
                page: "secrets",
              },
              {
                label: "SSH Keys",
                value: data.counts.ssh_keys,
                Icon: Terminal,
                page: "ssh",
              },
              {
                label: "WireGuard Configs",
                value: data.counts.wireguard,
                Icon: Network,
                page: "wireguard",
              },
              {
                label: "Expiring",
                value: data.counts.expiring,
                Icon: Clock,
                page: "secrets",
              },
            ].map((s, i) => (
              <button
                className={"stat-card stat-" + i}
                key={s.label}
                onClick={() => onOpen(s.page as "secrets")}
              >
                <div className="stat-top">
                  <span className="stat-icon">
                    <s.Icon size={21} />
                  </span>
                  <ArrowUpRight size={17} />
                </div>
                <span className="stat-number">{s.value}</span>
                <span className="stat-label">{s.label}</span>
                <span className="stat-foot">
                  {i === 3 ? "В ближайшие 30 дней" : "В защищённом хранилище"}
                </span>
              </button>
            ))}
          </div>
          <div className="dashboard-grid">
            <section className="panel">
              <div className="panel-heading">
                <h2>Recent Activity</h2>
                <span className="badge">Audit enabled</span>
              </div>
              {data.recent_activity.length ? (
                <ActivityList items={data.recent_activity.slice(0, 8)} />
              ) : (
                <Empty
                  title="История начинается здесь"
                  description="Создание, просмотр и копирование секретов появятся в журнале."
                  action={
                    canCreate ? (
                      <button className="button" onClick={onNew}>
                        Создать первый секрет
                      </button>
                    ) : undefined
                  }
                />
              )}
            </section>
            <div className="dashboard-side">
              <section className="panel security-overview">
                <div className="panel-heading">
                  <h2>Vault Overview</h2>
                  <ShieldCheck size={19} />
                </div>
                <div className="overview-row">
                  <span>Collections</span>
                  <strong>{data.counts.collections}</strong>
                </div>
                <div className="overview-row">
                  <span>Shared secrets</span>
                  <strong>{data.counts.shared}</strong>
                </div>
                <div className="overview-row">
                  <span>Expired secrets</span>
                  <strong className={data.counts.expired ? "danger-text" : ""}>
                    {data.counts.expired}
                  </strong>
                </div>
                <div className="encryption-note">
                  <ShieldCheck size={21} />
                  <div>
                    <strong>Encryption enabled</strong>
                    <span>AES-256-GCM · at rest</span>
                  </div>
                </div>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Security Warnings</h2>
                  <Clock size={17} />
                </div>
                {data.warnings.length ? (
                  data.warnings.map((w, i) => (
                    <p className="security-warning" key={i}>
                      {w}
                    </p>
                  ))
                ) : (
                  <p className="panel-text muted">
                    Нет активных предупреждений.
                  </p>
                )}
              </section>
            </div>
          </div>
        </>
      )}
    </>
  );
}
export function SecretList({
  items,
  collections,
  title,
  subtitle,
  loading,
  error,
  search,
  setSearch,
  onSelect,
  onNew,
  onImport,
  canCreate,
  filterCollection,
  setFilterCollection,
}: {
  items: Secret[];
  collections: Collection[];
  title: string;
  subtitle: string;
  loading: boolean;
  error: string;
  search: string;
  setSearch: (s: string) => void;
  onSelect: (s: Secret) => void;
  onNew: () => void;
  onImport: () => void;
  canCreate: boolean;
  filterCollection: string;
  setFilterCollection: (s: string) => void;
}) {
  const [type, setType] = useState(""),
    [tag, setTag] = useState("");
  const tags = [...new Set(items.flatMap((s) => s.tags))];
  const filtered = items.filter(
    (s) => (!type || s.type === type) && (!tag || s.tags.includes(tag)),
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">ENCRYPTED WORKSPACE</span>
          <h1>
            {title}
            <span className="count-chip">{items.length}</span>
          </h1>
          <p>{subtitle}</p>
        </div>
        {canCreate && (
          <div className="button-row">
            <button className="button" onClick={onImport}>
              <Upload size={16} /> Import
            </button>
            <button className="button primary" onClick={onNew}>
              <Plus size={17} /> New Secret
            </button>
          </div>
        )}
      </div>
      <div className="list-toolbar">
        <div className="search-input">
          <Search size={18} />
          <input
            aria-label="Поиск секретов"
            placeholder="Search by name, tag, service…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <kbd>⌘ K</kbd>
        </div>
        <div className="filter-group">
          <SlidersHorizontal size={17} />
          <select
            aria-label="Тип секрета"
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            <option value="">All types</option>
            {Object.entries(TYPES).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
          <select
            aria-label="Collection"
            value={filterCollection}
            onChange={(e) => setFilterCollection(e.target.value)}
          >
            <option value="">All collections</option>
            <option value="personal">Personal</option>
            {collections.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
          <select
            aria-label="Tag"
            value={tag}
            onChange={(e) => setTag(e.target.value)}
          >
            <option value="">All tags</option>
            {tags.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
      </div>
      <ErrorBox error={error} />
      {loading ? (
        <Loading />
      ) : !filtered.length ? (
        <div className="panel">
          <Empty
            title={search ? "Ничего не найдено" : "Секретов пока нет"}
            description={
              search
                ? "Попробуйте другое название, тег или collection."
                : "Сохраните пароль, ключ или конфигурацию. Значения будут скрыты до явного просмотра."
            }
            action={
              canCreate ? (
                <button className="button primary" onClick={onNew}>
                  <Plus size={16} /> New Secret
                </button>
              ) : undefined
            }
          />
        </div>
      ) : (
        <div className="panel table-wrap">
          <table className="secrets-table">
            <thead>
              <tr>
                <th>Name</th>
                {title === "SSH Keys" ? (
                  <>
                    <th>Host</th>
                    <th>User</th>
                    <th>Fingerprint</th>
                    <th>Created</th>
                    <th>Last used</th>
                  </>
                ) : title === "WireGuard" ? (
                  <>
                    <th>Endpoint</th>
                    <th>Client IP</th>
                    <th>Collection</th>
                    <th>Tags</th>
                  </>
                ) : (
                  <>
                    <th>Collection</th>
                    <th>Tags</th>
                    <th>Expires</th>
                    <th>Updated</th>
                  </>
                )}
                <th />
              </tr>
            </thead>
            <tbody>
              {filtered.map((s) => (
                <tr key={s.id} onClick={() => onSelect(s)}>
                  <td>
                    <button
                      className="secret-name"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelect(s);
                      }}
                    >
                      <span className={"secret-icon " + s.type}>
                        <TypeIcon type={s.type} />
                      </span>
                      <span>
                        <strong>{s.name}</strong>
                        <small>
                          {TYPES[s.type]}
                          {s.metadata.hostname
                            ? " · " + s.metadata.hostname
                            : s.metadata.service
                              ? " · " + s.metadata.service
                              : ""}
                        </small>
                      </span>
                    </button>
                  </td>
                  {title === "SSH Keys" ? (
                    <>
                      <td>{s.metadata.hostname || s.metadata.host || "—"}</td>
                      <td>{s.metadata.username || "—"}</td>
                      <td className="mono fingerprint-cell">
                        {s.metadata.fingerprint || "—"}
                      </td>
                      <td>
                        <DateText value={s.created_at} />
                      </td>
                      <td>
                        <DateText value={s.last_used} />
                      </td>
                    </>
                  ) : (
                    <>
                      {title === "WireGuard" && (
                        <>
                          <td>
                            {s.metadata.endpoint || s.metadata.hostname || "—"}
                          </td>
                          <td className="mono">{s.metadata.address || "—"}</td>
                        </>
                      )}
                      <td>
                        <span className="collection-label">
                          <Folder size={14} />
                          {collections.find((c) => c.id === s.collection_id)
                            ?.name || "Personal"}
                        </span>
                      </td>
                      <td>
                        <div className="tag-list">
                          {s.tags.slice(0, 2).map((t) => (
                            <span className="tag" key={t}>
                              {t}
                            </span>
                          ))}
                          {s.tags.length > 2 && (
                            <span className="tag">+{s.tags.length - 2}</span>
                          )}
                        </div>
                      </td>
                      {title !== "WireGuard" && (
                        <>
                          <td>
                            <Expiry date={s.expires_at} />
                            {!s.expires_at && <span className="muted">—</span>}
                          </td>
                          <td className="muted">
                            <DateText value={s.updated_at} />
                          </td>
                        </>
                      )}
                    </>
                  )}
                  <td>
                    <MoreHorizontal size={18} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="list-foot">
        <ShieldCheck size={14} /> Значения скрыты · поиск только по метаданным
      </div>
    </>
  );
}
export function CollectionsPage({
  collections,
  secrets,
  onOpen,
  onReload,
  notify,
  canCreate,
}: {
  collections: Collection[];
  secrets: Secret[];
  onOpen: (id: string) => void;
  onReload: () => void;
  notify: (s: string) => void;
  canCreate: boolean;
}) {
  const [edit, setEdit] = useState<Collection | null | undefined>(undefined),
    [access, setAccess] = useState<string | null>(null),
    [error, setError] = useState("");
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">ORGANIZE YOUR VAULT</span>
          <h1>
            Collections<span className="count-chip">{collections.length}</span>
          </h1>
          <p>Объединяйте секреты и назначайте доступ к каждому разделу.</p>
        </div>
        {canCreate && (
          <button className="button primary" onClick={() => setEdit(null)}>
            <Plus size={17} /> New Collection
          </button>
        )}
      </div>
      <ErrorBox error={error} />
      <div className="collection-grid">
        {collections.map((c) => (
          <article className="panel collection-card" key={c.id}>
            <button className="collection-main" onClick={() => onOpen(c.id)}>
              <span
                className="collection-icon"
                style={{ color: c.color, background: c.color + "18" }}
              >
                {c.icon === "server" ? (
                  <Server size={27} />
                ) : c.icon === "network" ? (
                  <Network size={27} />
                ) : c.icon === "key" ? (
                  <KeyRound size={27} />
                ) : c.icon === "shield" ? (
                  <ShieldCheck size={27} />
                ) : (
                  <Folder size={27} />
                )}
              </span>
              <h2>{c.name}</h2>
              <p>{c.description || "Collection"}</p>
              <span className="badge">
                {secrets.filter((s) => s.collection_id === c.id).length} secrets
              </span>
            </button>
            {c.can_edit && (
              <div className="collection-actions">
                {c.can_manage && (
                  <button
                    className="text-button"
                    onClick={() => setAccess(c.id)}
                  >
                    <Users size={15} /> Permissions
                  </button>
                )}
                <button
                  className="icon-button"
                  aria-label="Edit collection"
                  onClick={() => setEdit(c)}
                >
                  <Pencil size={16} />
                </button>
                {c.can_manage && (
                  <button
                    className="icon-button"
                    aria-label="Delete collection"
                    onClick={async () => {
                      if (
                        !confirm(
                          "Удалить collection? Секреты останутся в личном хранилище владельцев.",
                        )
                      )
                        return;
                      try {
                        await request("/collections/" + c.id, {}, "DELETE");
                        onReload();
                        notify("Collection удалена");
                      } catch (e) {
                        setError(safeError(e));
                      }
                    }}
                  >
                    <Trash2 size={16} />
                  </button>
                )}
              </div>
            )}
          </article>
        ))}
      </div>
      {!collections.length && (
        <div className="panel">
          <Empty
            title="Создайте свою первую collection"
            description="Например, Infrastructure, VPN или Personal."
            action={
              canCreate ? (
                <button
                  className="button primary"
                  onClick={() => setEdit(null)}
                >
                  Создать collection
                </button>
              ) : undefined
            }
          />
        </div>
      )}
      {edit !== undefined && (
        <CollectionForm
          item={edit}
          onClose={() => setEdit(undefined)}
          onSaved={() => {
            setEdit(undefined);
            onReload();
            notify("Collection сохранена");
          }}
        />
      )}
      {access && (
        <AccessDialog
          kind="collection"
          id={access}
          onClose={() => setAccess(null)}
          notify={notify}
        />
      )}
    </>
  );
}
function CollectionForm({
  item,
  onClose,
  onSaved,
}: {
  item: Collection | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(item?.name || ""),
    [description, setDescription] = useState(item?.description || ""),
    [color, setColor] = useState(item?.color || "#9d8bff"),
    [icon, setIcon] = useState(item?.icon || "folder"),
    [error, setError] = useState("");
  return (
    <Modal
      title={item ? "Edit Collection" : "New Collection"}
      onClose={onClose}
    >
      <form
        onSubmit={submit(async () => {
          try {
            await request(
              "/collections" + (item ? "/" + item.id : ""),
              { name, description, color, icon },
              item ? "PUT" : "POST",
            );
            onSaved();
          } catch (e) {
            setError(safeError(e));
          }
        })}
      >
        <Field label="Название">
          <input
            required
            maxLength={120}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>
        <Field label="Описание">
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <div className="form-grid">
          <Field label="Цвет">
            <input
              type="color"
              value={color}
              onChange={(e) => setColor(e.target.value)}
            />
          </Field>
          <Field label="Иконка">
            <select value={icon} onChange={(e) => setIcon(e.target.value)}>
              <option value="folder">Folder</option>
              <option value="server">Server</option>
              <option value="network">Network</option>
              <option value="key">Key</option>
              <option value="shield">Shield</option>
            </select>
          </Field>
        </div>
        <ErrorBox error={error} />
        <button className="button primary">Сохранить</button>
      </form>
    </Modal>
  );
}
export function AuditPage() {
  const [items, setItems] = useState<Activity[]>([]),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true),
    [search, setSearch] = useState("");
  useEffect(() => {
    request<Activity[]>("/audit")
      .then(setItems)
      .catch((e) => setError(safeError(e)))
      .finally(() => setLoading(false));
  }, []);
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">ACCOUNTABILITY</span>
          <h1>Audit Log</h1>
          <p>Кто и когда обращался к хранилищу. Без значений секретов.</p>
        </div>
        <span className="badge success">
          <ActivityIcon size={14} /> Logging enabled
        </span>
      </div>
      <div className="search-input audit-search">
        <Search size={17} />
        <input
          placeholder="Поиск в загруженных событиях…"
          aria-label="Поиск событий"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>
      <ErrorBox error={error} />
      {loading ? (
        <Loading />
      ) : (
        <div className="panel table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>User</th>
                <th>Action</th>
                <th>Target</th>
                <th>IP</th>
              </tr>
            </thead>
            <tbody>
              {items
                .filter((i) =>
                  [i.username, i.action, actionLabel(i.action), i.target, i.ip]
                    .join(" ")
                    .toLowerCase()
                    .includes(search.toLowerCase()),
                )
                .map((i) => (
                  <tr key={i.id}>
                    <td>
                      <DateText value={i.created_at} />
                    </td>
                    <td>{i.username || "anonymous"}</td>
                    <td>
                      <span className="badge">{actionLabel(i.action)}</span>
                    </td>
                    <td>{i.target || "—"}</td>
                    <td className="mono muted">{i.ip || "—"}</td>
                  </tr>
                ))}
            </tbody>
          </table>
          {!items.length && (
            <Empty
              title="Событий нет"
              description="Действия пользователей появятся здесь."
            />
          )}
        </div>
      )}
    </>
  );
}
export function UsersPage({
  notify,
  currentId,
  reauth,
}: {
  notify: (s: string) => void;
  currentId: string;
  reauth: (action: () => Promise<void>) => void;
}) {
  const [users, setUsers] = useState<User[]>([]),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true),
    [edit, setEdit] = useState<User | null | undefined>(undefined);
  async function load() {
    try {
      setUsers(await request("/users"));
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
          <span className="eyebrow">PEOPLE & ACCESS</span>
          <h1>Users</h1>
          <p>Роли и учётные записи вашего хранилища.</p>
        </div>
        <button className="button primary" onClick={() => setEdit(null)}>
          <Plus size={17} /> Add User
        </button>
      </div>
      <ErrorBox error={error} />
      {loading ? (
        <Loading />
      ) : (
        <div className="panel table-wrap">
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>2FA</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>
                    <div className="user-cell">
                      <span className="avatar">
                        {u.username.slice(0, 2).toUpperCase()}
                      </span>
                      <strong>{u.username}</strong>
                      {u.id === currentId && (
                        <small className="muted">you</small>
                      )}
                    </div>
                  </td>
                  <td>
                    <span className="badge">{u.role}</span>
                  </td>
                  <td>{u.totp_enabled ? "Enabled" : "Disabled"}</td>
                  <td>{u.disabled ? "Disabled" : "Active"}</td>
                  <td>
                    <button className="button small" onClick={() => setEdit(u)}>
                      Edit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {edit !== undefined && (
        <UserForm
          reauth={reauth}
          user={edit}
          onClose={() => setEdit(undefined)}
          onSaved={() => {
            setEdit(undefined);
            void load();
            notify("Пользователь сохранён");
          }}
        />
      )}
    </>
  );
}
function UserForm({
  user,
  onClose,
  onSaved,
  reauth,
}: {
  user: User | null;
  onClose: () => void;
  onSaved: () => void;
  reauth: (action: () => Promise<void>) => void;
}) {
  const [username, setUsername] = useState(user?.username || ""),
    [password, setPassword] = useState(""),
    [role, setRole] = useState(user?.role || "viewer"),
    [disabled, setDisabled] = useState(user?.disabled || false),
    [error, setError] = useState("");
  return (
    <Modal title={user ? "Edit User" : "Add User"} onClose={onClose}>
      <form
        onSubmit={submit(async () => {
          const save = async () => {
            try {
              await request(
                "/users" + (user ? "/" + user.id : ""),
                user
                  ? { role, disabled, ...(password ? { password } : {}) }
                  : { username, password, role },
                user ? "PUT" : "POST",
              );
              onSaved();
            } catch (e) {
              setError(safeError(e));
            }
          };
          if (user) reauth(save);
          else await save();
        })}
      >
        <Field label="Username">
          <input
            required
            disabled={!!user}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </Field>
        <Field label={user ? "Новый пароль (необязательно)" : "Пароль"}>
          <input
            type="password"
            autoComplete="new-password"
            minLength={12}
            required={!user}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
        <Field label="Role">
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as typeof role)}
          >
            <option value="admin">Admin — полный доступ</option>
            <option value="editor">Editor — создание и изменение</option>
            <option value="viewer">Viewer — чтение разрешённых секретов</option>
          </select>
        </Field>
        {user && (
          <label className="checkbox">
            <input
              type="checkbox"
              checked={disabled}
              onChange={(e) => setDisabled(e.target.checked)}
            />{" "}
            Отключить пользователя
          </label>
        )}
        <ErrorBox error={error} />
        <button className="button primary">Сохранить</button>
      </form>
    </Modal>
  );
}
