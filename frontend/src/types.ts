export type Role = "admin" | "editor" | "viewer";
export interface User {
  id: string;
  username: string;
  role: Role;
  totp_enabled: boolean;
  disabled?: boolean;
}
export interface Settings {
  instance_name: string;
  app_url: string;
  lock_timeout: number;
  session_hours: number;
  backup_enabled: boolean;
  backup_hour: number;
  retention_daily: number;
  retention_weekly: number;
  retention_monthly: number;
}
export interface Session {
  user: User | null;
  csrf_token: string;
  settings: Pick<Settings, "instance_name" | "app_url" | "lock_timeout">;
  setup_required: boolean;
  locked?: boolean;
}
export type SecretType =
  | "login"
  | "api_key"
  | "token"
  | "ssh_key"
  | "wireguard"
  | "environment"
  | "certificate"
  | "note"
  | "file";
export interface Secret {
  id: string;
  name: string;
  type: SecretType;
  collection_id: string | null;
  tags: string[];
  expires_at: string | null;
  metadata: Record<string, string>;
  created_at: string;
  updated_at: string;
  owner_id: string;
  version: number;
  last_used: string | null;
  can_edit: boolean;
  can_copy: boolean;
  can_share: boolean;
}
export interface Collection {
  id: string;
  name: string;
  description: string;
  icon: string;
  color: string;
  can_edit: boolean;
  can_manage: boolean;
}
export interface Activity {
  id: string;
  created_at: string;
  username: string;
  action: string;
  target: string;
  ip: string;
}
export interface DashboardData {
  counts: {
    secrets: number;
    collections: number;
    ssh_keys: number;
    wireguard: number;
    shared: number;
    expiring: number;
    expired: number;
  };
  recent_activity: Activity[];
  warnings: string[];
}
export interface Version {
  id: string;
  number: number;
  created_at: string;
  username: string;
  changed_fields: string[];
}
export interface Permission {
  user_id: string;
  access: "read" | "write" | "none";
  can_copy: boolean;
}
export interface TemporaryLink {
  id: string;
  secret_id: string;
  secret_name?: string;
  name?: string;
  expires_at: string;
  views: number;
  max_views: number;
  allow_copy: boolean;
  revoked?: boolean;
  created_at: string;
}
export interface Backup {
  id: string;
  filename: string;
  created_at: string;
  kind?: string;
}
export interface Security {
  encryption: boolean;
  https: boolean;
  master_key: boolean;
  totp_enabled: boolean;
  last_backup: string | null;
  failed_logins: number;
  weak_passwords: number;
  expired_secrets: number;
}
export const TYPES: Record<SecretType, string> = {
  login: "Login",
  api_key: "API Key",
  token: "Token",
  ssh_key: "SSH Key",
  wireguard: "WireGuard",
  environment: "Environment",
  certificate: "Certificate",
  note: "Secure Note",
  file: "File",
};
export type Page =
  | "dashboard"
  | "secrets"
  | "collections"
  | "shared"
  | "temporary"
  | "ssh"
  | "wireguard"
  | "audit"
  | "users"
  | "settings";
