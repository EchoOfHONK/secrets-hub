let csrfToken = "";
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export function setCsrf(token: string) {
  csrfToken = token;
}
export async function request<T>(
  path: string,
  body?: unknown,
  method?: string,
): Promise<T> {
  const response = await fetch("/api" + path, {
    method: method ?? (body === undefined ? "GET" : "POST"),
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let detail = "Не удалось выполнить запрос";
    try {
      const data = await response.json();
      if (typeof data.detail === "string") detail = data.detail;
    } catch {
      /* Response body may be empty. */
    }
    if (
      (response.status === 401 && detail === "Authentication required") ||
      (response.status === 403 && detail === "CSRF verification failed")
    )
      window.dispatchEvent(new Event("session-expired"));
    if (response.status === 423)
      window.dispatchEvent(new Event("vault-locked"));
    throw new ApiError(detail, response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
export async function downloadApi(
  path: string,
  body: unknown,
  filename: string,
) {
  const response = await fetch("/api" + path, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    if (response.status === 423)
      window.dispatchEvent(new Event("vault-locked"));
    const d = await response
      .json()
      .catch(() => ({ detail: "Ошибка загрузки" }));
    if (
      (response.status === 401 && d.detail === "Authentication required") ||
      (response.status === 403 && d.detail === "CSRF verification failed")
    )
      window.dispatchEvent(new Event("session-expired"));
    throw new ApiError(
      typeof d.detail === "string" ? d.detail : "Ошибка загрузки",
      response.status,
    );
  }
  downloadBlob(await response.blob(), filename);
}
export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.hidden = true;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
export function downloadText(
  text: string,
  filename: string,
  type = "text/plain",
) {
  downloadBlob(new Blob([text], { type }), filename);
}
export async function fileBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 8192)
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}
export async function copyText(value: string) {
  if (!navigator.clipboard || !window.isSecureContext)
    throw new Error("Для копирования нужен HTTPS или localhost.");
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      navigator.clipboard.writeText(value),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              new Error(
                "Браузер не разрешил копирование. Проверьте доступ к clipboard.",
              ),
            ),
          4000,
        );
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
