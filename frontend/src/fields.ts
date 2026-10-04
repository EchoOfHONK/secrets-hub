import type { SecretType } from "./types";
export interface SecretField {
  key: string;
  label: string;
  multiline?: boolean;
  sensitive?: boolean;
  optional?: boolean;
}
export const FIELDS: Record<SecretType, SecretField[]> = {
  login: [
    { key: "username", label: "Username" },
    { key: "password", label: "Password", sensitive: true },
    { key: "url", label: "URL", optional: true },
    {
      key: "notes",
      label: "Notes",
      multiline: true,
      optional: true,
      sensitive: true,
    },
  ],
  api_key: [
    { key: "service", label: "Service" },
    { key: "key", label: "Key", sensitive: true },
    { key: "secret", label: "Secret", sensitive: true, optional: true },
    { key: "environment", label: "Environment", optional: true },
    {
      key: "notes",
      label: "Notes",
      multiline: true,
      optional: true,
      sensitive: true,
    },
  ],
  token: [
    { key: "service", label: "Service" },
    { key: "token", label: "Token", sensitive: true, multiline: true },
  ],
  ssh_key: [
    { key: "host", label: "Host" },
    { key: "username", label: "Username", optional: true },
    {
      key: "private_key",
      label: "Private key",
      sensitive: true,
      multiline: true,
      optional: true,
    },
    { key: "public_key", label: "Public key", multiline: true, optional: true },
    { key: "passphrase", label: "Passphrase", sensitive: true, optional: true },
    { key: "fingerprint", label: "Fingerprint", optional: true },
    {
      key: "notes",
      label: "Notes",
      sensitive: true,
      multiline: true,
      optional: true,
    },
  ],
  wireguard: [
    { key: "endpoint", label: "Endpoint" },
    { key: "address", label: "Client IP" },
    { key: "dns", label: "DNS", optional: true },
    { key: "public_key", label: "Server public key" },
    { key: "interface_public_key", label: "Client public key", optional: true },
    { key: "private_key", label: "Client private key", sensitive: true },
    {
      key: "preshared_key",
      label: "Preshared key",
      sensitive: true,
      optional: true,
    },
    { key: "allowed_ips", label: "AllowedIPs" },
    {
      key: "persistent_keepalive",
      label: "PersistentKeepalive",
      optional: true,
    },
    {
      key: "config",
      label: "Config file (.conf)",
      sensitive: true,
      multiline: true,
      optional: true,
    },
    {
      key: "notes",
      label: "Notes",
      sensitive: true,
      multiline: true,
      optional: true,
    },
  ],
  environment: [
    { key: "content", label: "KEY=value", sensitive: true, multiline: true },
  ],
  certificate: [
    { key: "hostname", label: "Hostname" },
    { key: "issuer", label: "Issuer", optional: true },
    { key: "certificate", label: "Certificate", multiline: true },
    {
      key: "private_key",
      label: "Private key",
      sensitive: true,
      multiline: true,
      optional: true,
    },
    {
      key: "notes",
      label: "Notes",
      sensitive: true,
      multiline: true,
      optional: true,
    },
  ],
  note: [
    { key: "content", label: "Secret text", multiline: true, sensitive: true },
  ],
  file: [
    { key: "filename", label: "File name" },
    { key: "content_type", label: "Content type" },
  ],
};
