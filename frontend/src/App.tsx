import { useCallback, useEffect, useRef, useState } from "react";
import {
  ShieldCheck,
  LayoutDashboard,
  KeyRound,
  Folder,
  Share2,
  Link,
  Terminal,
  Network,
  History,
  Users,
  Settings,
  Search,
  LockKeyhole,
  LogOut,
  Menu,
  X,
  Check,
  WandSparkles,
} from "lucide-react";
import { request, setCsrf, copyText } from "./api";
import { Loading, safeError } from "./ui";
import { Login, Setup, LockScreen, Reauth } from "./Auth";
import { SecretForm, ImportDialog, Generator } from "./SecretForm";
import { SecretDetail } from "./SecretDetail";
import {
  Dashboard,
  SecretList,
  CollectionsPage,
  AuditPage,
  UsersPage,
} from "./VaultPages";
import { TemporaryPage } from "./Sharing";
import { SettingsPage } from "./SettingsPage";
import { PublicLink } from "./PublicLink";
import type { Session, Page, Collection, Secret, SecretType } from "./types";
const navigation: { id: Page; label: string; Icon: typeof KeyRound }[] = [
  { id: "dashboard", label: "Dashboard", Icon: LayoutDashboard },
  { id: "secrets", label: "Secrets", Icon: KeyRound },
  { id: "collections", label: "Collections", Icon: Folder },
  { id: "shared", label: "Shared", Icon: Share2 },
  { id: "temporary", label: "Temporary Access", Icon: Link },
  { id: "ssh", label: "SSH Keys", Icon: Terminal },
  { id: "wireguard", label: "WireGuard", Icon: Network },
  { id: "audit", label: "Audit Log", Icon: History },
  { id: "users", label: "Users", Icon: Users },
  { id: "settings", label: "Settings", Icon: Settings },
];
export default function App() {
  const [session, setSession] = useState<Session | null>(null),
    [boot, setBoot] = useState(true),
    [bootError, setBootError] = useState(""),
    [page, setPage] = useState<Page>("dashboard"),
    [locked, setLocked] = useState(false);
  const applySession = useCallback((s: Session) => {
    setCsrf(s.csrf_token);
    setSession(s);
    setLocked(!!s.locked);
  }, []);
  const fetchSession = useCallback(async () => {
    try {
      applySession(await request("/auth/session"));
      setBootError("");
    } catch (e) {
      setBootError(safeError(e));
    } finally {
      setBoot(false);
    }
  }, [applySession]);
  useEffect(() => {
    if (location.pathname === "/t") return;
    void fetchSession();
    const expired = () => {
      setSession(null);
      setCsrf("");
      setBoot(true);
      setLocked(false);
      void fetchSession();
    };
    const lock = () => setLocked(true);
    window.addEventListener("session-expired", expired);
    window.addEventListener("vault-locked", lock);
    return () => {
      window.removeEventListener("session-expired", expired);
      window.removeEventListener("vault-locked", lock);
    };
  }, [fetchSession]);
  useEffect(() => {
    document.documentElement.classList.toggle(
      "compact",
      localStorage.getItem("sh-compact") === "true",
    );
    document.documentElement.classList.toggle(
      "reduce-motion",
      localStorage.getItem("sh-reduce-motion") === "true",
    );
  }, []);
  if (location.pathname === "/t") return <PublicLink />;
  if (boot)
    return (
      <div className="boot">
        <ShieldCheck size={40} />
        <Loading />
      </div>
    );
  if (!session)
    return (
      <div className="boot">
        <p>{bootError}</p>
        <button
          className="button"
          onClick={() => {
            setBoot(true);
            void fetchSession();
          }}
        >
          Повторить подключение
        </button>
      </div>
    );
  if (session.setup_required)
    return <Setup initial={session} onSession={applySession} />;
  if (!session.user) return <Login onSession={applySession} />;
  if (locked) return <LockScreen onUnlock={() => void fetchSession()} />;
  return (
    <Workspace
      session={session}
      onSession={applySession}
      page={page}
      setPage={setPage}
      onLock={() => {
        setLocked(true);
        void request("/auth/lock", {}).catch(() => {});
      }}
    />
  );
}
function Workspace({
  session,
  onSession,
  page,
  setPage,
  onLock,
}: {
  session: Session;
  onSession: (s: Session) => void;
  page: Page;
  setPage: (p: Page) => void;
  onLock: () => void;
}) {
  const [collections, setCollections] = useState<Collection[]>([]),
    [secrets, setSecrets] = useState<Secret[]>([]),
    [allSecrets, setAllSecrets] = useState<Secret[]>([]),
    [search, setSearch] = useState(""),
    [globalSearch, setGlobalSearch] = useState(""),
    [collection, setCollection] = useState(""),
    [loading, setLoading] = useState(true),
    [error, setError] = useState(""),
    [selected, setSelected] = useState<Secret | null>(null),
    [form, setForm] = useState<{
      existing?: Secret;
      data?: Record<string, string>;
      type?: SecretType;
    } | null>(null),
    [importing, setImporting] = useState(false),
    [revision, setRevision] = useState(0),
    [mobile, setMobile] = useState(false),
    [toast, setToast] = useState(""),
    [authAction, setAuthAction] = useState<(() => Promise<void>) | null>(null),
    [generator, setGenerator] = useState(false);
  const notify = useCallback((msg: string) => setToast(msg), []);
  const canCreate = session.user?.role !== "viewer";
  const searchRef = useRef<HTMLInputElement>(null),
    lastActivity = useRef(Date.now());
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(""), 6000);
    return () => clearTimeout(t);
  }, [toast]);
  useEffect(() => {
    const fn = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    document.addEventListener("keydown", fn);
    return () => document.removeEventListener("keydown", fn);
  }, []);
  useEffect(() => {
    const update = () => {
      lastActivity.current = Date.now();
    };
    for (const event of ["pointerdown", "keydown", "touchstart"])
      window.addEventListener(event, update, { passive: true });
    const timer = setInterval(() => {
      if (
        session.settings.lock_timeout &&
        Date.now() - lastActivity.current >
          session.settings.lock_timeout * 60000
      )
        onLock();
    }, 1000);
    const heartbeat = setInterval(() => {
      if (Date.now() - lastActivity.current < 25000)
        void request("/auth/activity", {}).catch(() => {});
    }, 20000);
    return () => {
      clearInterval(heartbeat);
      clearInterval(timer);
      for (const event of ["pointerdown", "keydown", "touchstart"])
        window.removeEventListener(event, update);
    };
  }, [session.settings.lock_timeout, onLock]);
  useEffect(() => {
    let cancel = false;
    setLoading(true);
    const timer = setTimeout(async () => {
      try {
        const [c, a, s] = await Promise.all([
          request<Collection[]>("/collections"),
          request<Secret[]>("/secrets"),
          page === "shared"
            ? request<Secret[]>("/shared")
            : request<Secret[]>(
                "/secrets?" +
                  new URLSearchParams({
                    ...(search ? { search } : {}),
                    ...(page === "ssh"
                      ? { type: "ssh_key" }
                      : page === "wireguard"
                        ? { type: "wireguard" }
                        : {}),
                  }),
              ),
        ]);
        if (!cancel) {
          setCollections(c);
          setAllSecrets(a);
          setSecrets(s);
          setError("");
        }
      } catch (e) {
        if (!cancel) setError(safeError(e));
      } finally {
        if (!cancel) setLoading(false);
      }
    }, 200);
    return () => {
      cancel = true;
      clearTimeout(timer);
    };
  }, [page, search, revision]);
  useEffect(() => {
    if (!globalSearch) {
      setSearch("");
      return;
    }
    setPage("secrets");
    setSearch(globalSearch);
    setCollection("");
  }, [globalSearch, setPage]);
  function navigate(p: Page) {
    setPage(p);
    setMobile(false);
    setCollection("");
    setSearch("");
    setGlobalSearch("");
  }
  function refresh() {
    setRevision((v) => v + 1);
    setSelected(null);
    setForm(null);
    setImporting(false);
  }
  function newSecret() {
    setForm({
      type:
        page === "ssh"
          ? "ssh_key"
          : page === "wireguard"
            ? "wireguard"
            : undefined,
    });
  }
  const filtered = secrets.filter(
    (s) =>
      (!collection ||
        (collection === "personal"
          ? !s.collection_id
          : s.collection_id === collection)) &&
      (page !== "shared" ||
        !search ||
        [s.name, s.tags.join(" "), ...Object.values(s.metadata)]
          .join(" ")
          .toLowerCase()
          .includes(search.toLowerCase())),
  );
  return (
    <div className="app-shell">
      {mobile && (
        <div className="sidebar-backdrop" onClick={() => setMobile(false)} />
      )}
      <aside className={"sidebar " + (mobile ? "open" : "")}>
        <div className="sidebar-brand">
          <span className="brand-mark">
            <ShieldCheck size={25} />
          </span>
          <div>
            <strong>Secrets Hub</strong>
            <small>{session.settings.instance_name}</small>
          </div>
          <button
            className="icon-button mobile-close"
            onClick={() => setMobile(false)}
            aria-label="Закрыть меню"
          >
            <X size={19} />
          </button>
        </div>
        <div className="workspace-label">
          <span className="workspace-avatar">
            {session.settings.instance_name.slice(0, 1).toUpperCase()}
          </span>
          <span>
            {session.settings.instance_name}
            <small>Private workspace</small>
          </span>
        </div>
        <span className="nav-caption">WORKSPACE</span>
        <nav className="main-nav">
          {navigation.map(({ id, label, Icon }, i) => (
            <button
              className={
                (page === id ? "active " : "") + (i === 7 ? "nav-divider" : "")
              }
              key={id}
              disabled={id === "users" && session.user?.role !== "admin"}
              onClick={() => navigate(id)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {id === "secrets" && <small>{allSecrets.length}</small>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="vault-status">
            <ShieldCheck size={16} />
            <span>Vault encrypted</span>
            <span className="status-dot" />
          </div>
          <div className="profile">
            <span className="avatar">
              {session.user!.username.slice(0, 2).toUpperCase()}
            </span>
            <div>
              <strong>{session.user!.username}</strong>
              <small>{session.user!.role}</small>
            </div>
            <button
              className="icon-button"
              title="Logout"
              aria-label="Logout"
              onClick={async () => {
                try {
                  await request("/auth/logout", { all_devices: false });
                  window.dispatchEvent(new Event("session-expired"));
                } catch (e) {
                  notify(safeError(e));
                }
              }}
            >
              <LogOut size={17} />
            </button>
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <button
            className="icon-button mobile-menu"
            aria-label="Открыть меню"
            onClick={() => setMobile(true)}
          >
            <Menu size={21} />
          </button>
          <div className="breadcrumb">
            <span>Workspace</span>
            <span>/</span>
            <strong>{navigation.find((n) => n.id === page)?.label}</strong>
          </div>
          <div className="topbar-actions">
            <div className="global-search">
              <Search size={16} />
              <input
                ref={searchRef}
                aria-label="Глобальный поиск"
                placeholder="Search vault…"
                value={globalSearch}
                onChange={(e) => setGlobalSearch(e.target.value)}
              />
              <kbd>⌘ K</kbd>
            </div>
            <button
              className="icon-button"
              title="Generator"
              aria-label="Generator"
              onClick={() => setGenerator(true)}
            >
              <WandSparkles size={19} />
            </button>
            <button className="lock-button" onClick={onLock}>
              <LockKeyhole size={16} />
              <span>Lock vault</span>
            </button>
          </div>
        </header>
        <main className="main-content">
          {page === "dashboard" && (
            <Dashboard
              canCreate={canCreate}
              key={revision}
              onOpen={(p) => navigate(p)}
              onNew={newSecret}
            />
          )}
          {["secrets", "ssh", "wireguard", "shared"].includes(page) && (
            <SecretList
              key={page}
              items={filtered}
              collections={collections}
              title={
                page === "ssh"
                  ? "SSH Keys"
                  : page === "wireguard"
                    ? "WireGuard"
                    : page === "shared"
                      ? "Shared Secrets"
                      : collection && collection !== "personal"
                        ? collections.find((c) => c.id === collection)?.name ||
                          "Secrets"
                        : "Secrets"
              }
              subtitle={
                page === "ssh"
                  ? "Ключи доступа к серверам. Private key скрыт по умолчанию."
                  : page === "wireguard"
                    ? "Клиентские VPN-профили, .conf и QR-коды."
                    : page === "shared"
                      ? "Секреты, к которым вам предоставлен доступ."
                      : "Пароли, ключи и конфигурации вашей инфраструктуры."
              }
              loading={loading}
              error={error}
              search={search}
              setSearch={setSearch}
              onSelect={setSelected}
              onNew={newSecret}
              onImport={() => setImporting(true)}
              canCreate={canCreate}
              filterCollection={collection}
              setFilterCollection={setCollection}
            />
          )}
          {page === "collections" && (
            <CollectionsPage
              collections={collections}
              secrets={allSecrets}
              onOpen={(id) => {
                setPage("secrets");
                setCollection(id);
              }}
              onReload={refresh}
              notify={notify}
              canCreate={canCreate}
            />
          )}
          {page === "temporary" && (
            <TemporaryPage key={revision} notify={notify} />
          )}
          {page === "audit" && <AuditPage key={revision} />}
          {page === "users" && session.user?.role === "admin" && (
            <UsersPage
              reauth={(action) => setAuthAction(() => action)}
              notify={notify}
              currentId={session.user.id}
            />
          )}
          {page === "settings" && (
            <SettingsPage
              session={session}
              onSession={onSession}
              notify={notify}
              reauth={(action) => setAuthAction(() => action)}
              onNavigate={navigate}
            />
          )}
        </main>
        <footer className="workspace-footer">
          <span>Secrets Hub</span>
          <span>Ваш сервер. Ваши данные.</span>
          <span>
            <ShieldCheck size={13} /> Secure by design
          </span>
        </footer>
      </div>
      {toast && (
        <div className="toast" role="status">
          <Check size={19} />
          <span>{toast}</span>
          <button
            className="icon-button"
            aria-label="Закрыть уведомление"
            onClick={() => setToast("")}
          >
            <X size={16} />
          </button>
        </div>
      )}
      {selected && (
        <SecretDetail
          secret={selected}
          onClose={() => setSelected(null)}
          onEdit={(data) => {
            setForm({ existing: selected, data });
            setSelected(null);
          }}
          onChanged={refresh}
          notify={notify}
          reauth={(action) => setAuthAction(() => action)}
        />
      )}
      {form && (
        <SecretForm
          existing={form.existing}
          initialData={form.data}
          initialType={form.type}
          initialCollection={collection === "personal" ? undefined : collection}
          collections={collections}
          onClose={() => setForm(null)}
          onSaved={() => {
            notify("Секрет сохранён");
            refresh();
          }}
        />
      )}
      {importing && (
        <ImportDialog
          collections={collections}
          initialFormat={
            page === "ssh" ? "ssh" : page === "wireguard" ? "wireguard" : "json"
          }
          onClose={() => setImporting(false)}
          onSaved={() => {
            notify("Импорт завершён");
            refresh();
          }}
        />
      )}
      {authAction && (
        <Reauth
          onClose={() => setAuthAction(null)}
          onSuccess={() => {
            const action = authAction;
            setAuthAction(null);
            void action().catch((e) => notify(safeError(e)));
          }}
        />
      )}
      {generator && (
        <Generator
          onClose={() => setGenerator(false)}
          onUse={(value) => {
            void copyText(value)
              .then(() =>
                notify("Сгенерированное значение скопировано в clipboard"),
              )
              .catch((e) => notify(safeError(e)));
          }}
        />
      )}
    </div>
  );
}
