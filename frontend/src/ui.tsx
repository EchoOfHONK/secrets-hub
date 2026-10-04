import {
  useEffect,
  useRef,
  useId,
  cloneElement,
  isValidElement,
  Children,
  type ReactElement,
  type ReactNode,
  type FormEvent,
} from "react";
import {
  X,
  LoaderCircle,
  ShieldCheck,
  KeyRound,
  Globe,
  Terminal,
  Network,
  Braces,
  FileKey,
  StickyNote,
  File,
  AlertCircle,
} from "lucide-react";
import type { SecretType, Activity } from "./types";
import { actionLabel } from "./actions";
export function Modal({
  title,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const handle = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeRef.current();
      if (e.key === "Tab") {
        const nodes = ref.current?.querySelectorAll<HTMLElement>(
          'button:not([disabled]),input:not([disabled]),select,textarea,a[href],[tabindex="0"]',
        );
        if (!nodes?.length) return;
        const first = nodes[0],
          last = nodes[nodes.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", handle);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handle);
      document.body.style.overflow = "";
      previous?.focus();
    };
  }, []);
  return (
    <div
      className="modal-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        tabIndex={-1}
        className={"modal " + (wide ? "modal-wide" : "")}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <header>
          <h2>{title}</h2>
          <button
            className="icon-button"
            aria-label="Закрыть"
            onClick={onClose}
          >
            <X size={20} />
          </button>
        </header>
        {children}
      </div>
    </div>
  );
}
export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  const id = useId();
  function labeled(node: ReactNode): ReactNode {
    if (!isValidElement(node)) return node;
    const element = node as ReactElement<Record<string, unknown>>;
    if (
      typeof element.type === "string" &&
      ["input", "textarea", "select"].includes(element.type)
    )
      return cloneElement(element, {
        "aria-labelledby": id,
        "aria-describedby": hint ? id + "-hint" : undefined,
      });
    if (element.props.children)
      return cloneElement(element, {
        children: Children.map(element.props.children as ReactNode, labeled),
      });
    return node;
  }
  return (
    <label className="field">
      <span id={id}>{label}</span>
      {Children.map(children, labeled)}
      {hint && <small id={id + "-hint"}>{hint}</small>}
    </label>
  );
}
export function ErrorBox({ error }: { error: string }) {
  return error ? (
    <div role="alert" className="error">
      <AlertCircle size={17} />
      {error}
    </div>
  ) : null;
}
export function Loading() {
  return (
    <div className="loading">
      <LoaderCircle className="spin" size={22} />
      <span>Загрузка…</span>
    </div>
  );
}
export function Empty({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <ShieldCheck size={32} />
      </div>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}
export function TypeIcon({
  type,
  size = 18,
}: {
  type: SecretType;
  size?: number;
}) {
  const Icon = {
    login: Globe,
    api_key: KeyRound,
    token: FileKey,
    ssh_key: Terminal,
    wireguard: Network,
    environment: Braces,
    certificate: ShieldCheck,
    note: StickyNote,
    file: File,
  }[type];
  return <Icon size={size} />;
}
export function DateText({ value }: { value: string | null | undefined }) {
  if (!value) return <>—</>;
  const date = new Date(value);
  return (
    <time dateTime={value}>
      {isNaN(date.getTime())
        ? "—"
        : date.toLocaleString("ru-RU", {
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          })}
    </time>
  );
}
export function ActivityList({ items }: { items: Activity[] }) {
  return (
    <div className="activity-list">
      {items.map((item) => (
        <div className="activity" key={item.id}>
          <div className="activity-dot">
            <ShieldCheck size={16} />
          </div>
          <div className="activity-content">
            <strong>{item.target || "Secrets Hub"}</strong>
            <span>
              {actionLabel(item.action)} · {item.username || "anonymous"}
            </span>
          </div>
          <DateText value={item.created_at} />
        </div>
      ))}
    </div>
  );
}
export function Expiry({ date }: { date: string | null }) {
  if (!date) return null;
  const days = Math.ceil((new Date(date).getTime() - Date.now()) / 86400000);
  return (
    <span
      className={
        "badge " + (days <= 0 ? "danger" : days <= 30 ? "warning" : "")
      }
    >
      {days <= 0
        ? "Истёк"
        : days <= 1
          ? "Истекает сегодня"
          : days <= 30
            ? `${days} дн. до истечения`
            : new Date(date).toLocaleDateString("ru-RU")}
    </span>
  );
}
export function submit(action: () => Promise<unknown>) {
  return (event: FormEvent) => {
    event.preventDefault();
    void action();
  };
}
export function safeError(error: unknown) {
  return error instanceof Error
    ? error.message
    : "Не удалось выполнить действие";
}
