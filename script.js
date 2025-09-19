
// core.js — funciones compartidas para OrumGS
// Expone utilidades en window.Core para reusar en todas las páginas.

(function () {
  const API_URL = window.location.origin;

  // ===== Utilidades =====
  function $(sel, root = document) { return root.querySelector(sel); }
  function $all(sel, root = document) { return Array.from(root.querySelectorAll(sel)); }

  // Alertita simple (puedes personalizar con tu CSS)
  function showAlert(message, type = "info", ms = 3000) {
    let box = document.createElement("div");
    box.textContent = message;
    box.className = `fixed top-4 right-4 px-4 py-3 rounded shadow text-white z-50 ${type === "error" ? "bg-red-600" : type === "success" ? "bg-green-600" : "bg-blue-600"}`;
    document.body.appendChild(box);
    setTimeout(() => box.remove(), ms);
  }

  // ===== Auth =====
  async function login(email, password) {
    const res = await fetch(`${API_URL}/login`, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Error de login");
    localStorage.setItem("token", data.token);
    localStorage.setItem("user", JSON.stringify(data.user));
    return data.user;
  }

  async function register(nombre, email, password) {
    const res = await fetch(`${API_URL}/register`, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ nombre, email, password })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Error de registro");
    return data;
  }

  function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
  }

  function getToken() { return localStorage.getItem("token"); }
  function getUser() {
    try { return JSON.parse(localStorage.getItem("user") || "null"); }
    catch(_) { return null; }
  }

  async function checkLoginStatus() {
    const token = getToken();
    if (!token) return { ok:false };
    try {
      const res = await fetch(`${API_URL}/validate-token`, {
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (!res.ok) return { ok:false };
      const data = await res.json();
      return { ok:true, user: data.user };
    } catch {
      return { ok:false };
    }
  }

  async function requestPasswordReset(email) {
    const res = await fetch(`${API_URL}/auth/request-password-reset`, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ email })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Error solicitando reset");
    return data;
  }

  async function resetPasswordWithToken(email, token, password) {
    // Fijamos el bug: el backend espera `password`
    const res = await fetch(`${API_URL}/auth/reset-password`, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ email, token, password })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Error al restablecer");
    return data;
  }

  // ===== Admin Usuarios =====
  async function loadUsers() {
    const token = getToken();
    const res = await fetch(`${API_URL}/usuarios`, {
      headers: { "Authorization": `Bearer ${token}` }
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Error cargando usuarios");
    return data;
  }

  async function changeUserRole(userId, newRole) {
    const token = getToken();
    const res = await fetch(`${API_URL}/usuarios/${userId}/rol`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({ rol: newRole })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Error cambiando rol");
    return data;
  }

  async function deleteUser(userId) {
    const token = getToken();
    const res = await fetch(`${API_URL}/usuarios/${userId}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${token}` }
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Error eliminando usuario");
    return data;
  }

  // ===== Mercados / Precios =====
  function getNumericPrice(v) {
    if (v == null) return null;
    if (typeof v === "number") return v;
    const n = String(v).replace(/[^\d.-]/g, "");
    const num = Number(n);
    return isNaN(num) ? null : num;
  }

  async function fetchCryptoPrices() {
    const res = await fetch(`${API_URL}/crypto-prices`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Error al obtener precios");
    return data; // { bitcoin: number, ethereum: number, dogecoin: number }
  }

  async function fetchTopList() {
    const res = await fetch(`${API_URL}/top30-list`);
    let data;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok || !Array.isArray(data) || !data.length) {
      // fallback coherente
      data = [
        { key:"BTCUSDT", label:"BTCUSDT (BTC)", tv_symbol:"BINANCE:BTCUSDT", type:"crypto" },
        { key:"ETHUSDT", label:"ETHUSDT (ETH)", tv_symbol:"BINANCE:ETHUSDT", type:"crypto" },
        { key:"DOGEUSDT", label:"DOGEUSDT (DOGE)", tv_symbol:"BINANCE:DOGEUSDT", type:"crypto" },
      ];
    }
    return data;
  }

  async function fetchPrices(keys = []) {
    const query = keys.length ? `?keys=${encodeURIComponent(keys.join(","))}` : "";
    const res = await fetch(`${API_URL}/market-prices${query}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || "Error precios");
    return data; // { BTCUSDT: "12345.67", ... } (o números)
  }

  // ===== TradingView =====
  function ensureTradingView() {
    return new Promise((resolve, reject) => {
      if (window.TradingView && window.TradingView.widget) return resolve();
      const s = document.createElement("script");
      s.src = "https://s3.tradingview.com/tv.js";
      s.onload = () => resolve();
      s.onerror = () => reject(new Error("No se pudo cargar TradingView"));
      document.head.appendChild(s);
    });
  }

  async function loadChart(containerId, tvSymbol, options = {}) {
    await ensureTradingView();
    const defaults = {
      symbol: tvSymbol,
      interval: "1",
      timezone: "Etc/UTC",
      theme: "dark",
      style: "1",
      locale: "es",
      toolbar_bg: "#f1f3f6",
      enable_publishing: false,
      withdateranges: true,
      hide_side_toolbar: false,
      allow_symbol_change: true,
      save_image: false,
      width: "100%",
      height: 400,
      autosize: false,
      hide_volume: false,
      studies: []
    };
    const cfg = Object.assign({}, defaults, options);
    // eslint-disable-next-line no-new
    new window.TradingView.widget(Object.assign({ container_id: containerId }, cfg));
  }

  window.Core = {
    API_URL,
    // utils
    $, $all, showAlert, getNumericPrice,
    // auth
    login, register, logout, getToken, getUser, checkLoginStatus, requestPasswordReset, resetPasswordWithToken,
    // admin users
    loadUsers, changeUserRole, deleteUser,
    // markets
    fetchCryptoPrices, fetchTopList, fetchPrices, loadChart
  };
})();
