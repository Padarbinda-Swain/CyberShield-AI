const TOKEN_KEY = "cs_token";
export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (t) => (t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY));

export async function api(path, { method = "GET", body, form } = {}) {
  const headers = {};
  const t = getToken();
  if (t) headers.Authorization = `Bearer ${t}`;
  if (body) headers["Content-Type"] = "application/json";
  let res;
  try {
    res = await fetch(`/api${path}`, { method, headers, body: form || (body ? JSON.stringify(body) : undefined) });
  } catch {
    throw new Error("Can't reach the CyberShield server. Check that the backend is running.");
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && t && !path.startsWith("/auth/login")) { setToken(null); window.dispatchEvent(new Event("cs-logout")); }
    const d = data.detail;
    throw new Error(Array.isArray(d) ? d.map((x) => x.msg.replace("Value error, ", "")).join(". ") : d || "Something went wrong");
  }
  return data;
}
