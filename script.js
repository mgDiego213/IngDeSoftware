// Configuraciones principales
const API_URL = window.location.origin; // si usas proxy: "/api"
const CRYPTOS = ["bitcoin", "ethereum", "dogecoin"];
const TRADINGVIEW_SYMBOLS = {
  bitcoin: "BINANCE:BTCUSDT",
  ethereum: "BINANCE:ETHUSDT",
  dogecoin: "BINANCE:DOGEUSDT",
};

// Aplicación Vue
const app = Vue.createApp({
  data() {
    return {
      // Modales
      showLoginModal: false,
      showRegistroModal: false,
      showForgotModal: false,   // NUEVO
      // Formularios
      loginEmail: "",
      loginPassword: "",
      registerName: "",
      registerEmail: "",
      registerPassword: "",
      forgotEmail: "",          // NUEVO
      // Estado
      isLoggedIn: false,
      userRole: null,
      userId: null,
      activeTab: "dashboard",
      // Precios
      prices: {
        bitcoin: "Cargando...",
        ethereum: "Cargando...",
        dogecoin: "Cargando...",
      },
      previousPrices: { bitcoin: null, ethereum: null, dogecoin: null },
      priceDirections: { bitcoin: null, ethereum: null, dogecoin: null },
      lastUpdate: null,
      updateInterval: null,
      // Usuarios (admin)
      users: [],
      // Alerta personalizada
      showCustomAlert: false,
      customAlertMessage: "",
    };
  },

  methods: {
    // ------------------ Utilidades ------------------
    showAlert(message) {
      this.customAlertMessage = message;
      this.showCustomAlert = true;
    },

    // ------------------ Recuperación de contraseña ------------------
    async requestPasswordReset() {
      try {
        const res = await fetch(`${API_URL}/auth/request-password-reset`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: this.forgotEmail }),
        });
        const d = await res.json();
        this.showAlert(
          d.message ||
            "Si el correo existe, te enviaremos un enlace para restablecer."
        );
        this.forgotEmail = "";
        this.showForgotModal = false;
        this.showLoginModal = true;
      } catch {
        this.showAlert("Error de conexión. Intenta más tarde.");
      }
    },

    // ------------------ Sesión ------------------
    async checkLoginStatus() {
      const token = localStorage.getItem("token");
      this.userRole = localStorage.getItem("rol");
      this.userId = localStorage.getItem("userId");

      if (!token) {
        this.isLoggedIn = false;
        return;
      }

      try {
        const response = await fetch(`${API_URL}/validate-token`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });

        if (response.ok) {
          this.isLoggedIn = true;
          // Iniciar datos en sesión
          this.fetchCryptoPrices();
          this.startPriceUpdates();
          setTimeout(() => loadTradingViewCharts(), 1000);
          if (this.userRole === "Dueño" || this.userRole === "Gerente") {
            this.loadUsers();
          }
        } else {
          localStorage.removeItem("token");
          localStorage.removeItem("rol");
          localStorage.removeItem("userId");
          this.isLoggedIn = false;
        }
      } catch (error) {
        console.error("Error validando el token:", error);
        this.isLoggedIn = false;
      }
    },

    login() {
      fetch(`${API_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: this.loginEmail,
          password: this.loginPassword,
        }),
      })
        .then((r) => r.json())
        .then((data) => {
          if (data.token) {
            localStorage.setItem("token", data.token);
            localStorage.setItem("rol", data.rol);
            localStorage.setItem("userId", data.userId);

            this.isLoggedIn = true;
            this.userRole = data.rol;
            this.userId = data.userId;
            this.showLoginModal = false;

            this.fetchCryptoPrices();
            this.startPriceUpdates();
            setTimeout(() => loadTradingViewCharts(), 1000);
          } else {
            this.showAlert("Credenciales incorrectas");
          }
        })
        .catch((e) => {
          console.error("Error en login:", e);
          this.showAlert("Error de conexión. Intente nuevamente.");
        });
    },

    register() {
      fetch(`${API_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          nombre: this.registerName,
          email: this.registerEmail,
          password: this.registerPassword,
        }),
      })
        .then((r) => r.json())
        .then((data) => {
          this.showAlert(data.message);
          if (data.id) {
            // Autologin
            this.loginEmail = this.registerEmail;
            this.loginPassword = this.registerPassword;
            this.showRegistroModal = false;
            this.login();
          }
        })
        .catch((e) => {
          console.error("Error en registro:", e);
          this.showAlert("Error de conexión. Intente nuevamente.");
        });
    },

    logout() {
      if (typeof this.stopPriceUpdates === "function") this.stopPriceUpdates();
      localStorage.removeItem("token");
      localStorage.removeItem("rol");
      localStorage.removeItem("userId");
      this.isLoggedIn = false;
      this.userRole = null;
      this.userId = null;
      this.activeTab = "dashboard";
      window.location.replace("index.html");
    },

    // ------------------ Precios ------------------
    startPriceUpdates() {
      if (this.updateInterval) clearInterval(this.updateInterval);
      this.updateInterval = setInterval(() => this.fetchCryptoPrices(), 20000);
    },

    stopPriceUpdates() {
      if (this.updateInterval) {
        clearInterval(this.updateInterval);
        this.updateInterval = null;
      }
    },

    async fetchCryptoPrices() {
      if (!this.isLoggedIn) return;
      try {
        const response = await fetch(`${API_URL}/crypto-prices`);
        const data = await response.json();
        if (data.message) return;

        // Guardar previos
        this.previousPrices = {
          bitcoin: this.getNumericPrice(this.prices.bitcoin),
          ethereum: this.getNumericPrice(this.prices.ethereum),
          dogecoin: this.getNumericPrice(this.prices.dogecoin),
        };

        // Formatear nuevos
        const formattedBitcoin = data.bitcoin.usd.toLocaleString("en-US", {
          style: "currency",
          currency: "USD",
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        });
        const formattedEthereum = data.ethereum.usd.toLocaleString("en-US", {
          style: "currency",
          currency: "USD",
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        });
        const formattedDogecoin = data.dogecoin.usd.toLocaleString("en-US", {
          style: "currency",
          currency: "USD",
          minimumFractionDigits: 6,
          maximumFractionDigits: 6,
        });

        this.prices.bitcoin = formattedBitcoin;
        this.prices.ethereum = formattedEthereum;
        this.prices.dogecoin = formattedDogecoin;

        // Direcciones
        if (this.previousPrices.bitcoin !== null) {
          this.priceDirections.bitcoin =
            data.bitcoin.usd > this.previousPrices.bitcoin
              ? "up"
              : data.bitcoin.usd < this.previousPrices.bitcoin
              ? "down"
              : null;
          this.priceDirections.ethereum =
            data.ethereum.usd > this.previousPrices.ethereum
              ? "up"
              : data.ethereum.usd < this.previousPrices.ethereum
              ? "down"
              : null;
          this.priceDirections.dogecoin =
            data.dogecoin.usd > this.previousPrices.dogecoin
              ? "up"
              : data.dogecoin.usd < this.previousPrices.dogecoin
              ? "down"
              : null;
        }

        this.lastUpdate = new Date();

        // Limpiar flechas luego de 2s
        setTimeout(
          () =>
            (this.priceDirections = {
              bitcoin: null,
              ethereum: null,
              dogecoin: null,
            }),
          2000
        );
      } catch (error) {
        console.error("Error obteniendo precios:", error);
      }
    },

    getNumericPrice(formattedPrice) {
      if (formattedPrice === "Cargando...") return null;
      return parseFloat(formattedPrice.replace(/[$,]/g, ""));
    },

    // ------------------ Admin usuarios ------------------
    loadUsers() {
      const token = localStorage.getItem("token");
      fetch(`${API_URL}/usuarios`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((r) => r.json())
        .then((data) => {
          this.users = data;
          setTimeout(() => loadTradingViewCharts(), 1000);
        })
        .catch((e) => {
          console.error("Error al cargar usuarios:", e);
          this.showAlert("Error al cargar la lista de usuarios");
        });
    },

    changeUserRole(userId, currentRole) {
      const token = localStorage.getItem("token");
      const newRole = prompt(
        `Ingrese el nuevo rol para este usuario (actual: ${currentRole})\nOpciones: Dueño, Gerente, Trabajador, Usuario:`
      );
      if (
        !newRole ||
        !["Dueño", "Gerente", "Trabajador", "Usuario"].includes(newRole)
      ) {
        this.showAlert("Rol inválido.");
        return;
      }
      fetch(`${API_URL}/usuarios/${userId}/rol`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ rol: newRole }),
      })
        .then((r) => r.json())
        .then((d) => {
          this.showAlert(d.message);
          this.loadUsers();
        })
        .catch((e) => {
          console.error("Error al cambiar rol:", e);
          this.showAlert("Error al cambiar el rol");
        });
    },

    deleteUser(userId) {
      const token = localStorage.getItem("token");
      if (!confirm("¿Estás seguro de eliminar este usuario?")) return;
      fetch(`${API_URL}/usuarios/${userId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((r) => r.json())
        .then((d) => {
          this.showAlert(d.message);
          this.loadUsers();
        })
        .catch((e) => {
          console.error("Error al eliminar usuario:", e);
          this.showAlert("Error al eliminar usuario");
        });
    },
  },

  mounted() {
    this.checkLoginStatus();
  },

  beforeUnmount() {
    this.stopPriceUpdates();
  },
}).mount("#app");

// ------------------ TradingView ------------------
function loadTradingViewCharts() {
  setTimeout(() => {
    CRYPTOS.forEach((crypto) => {
      const chartDiv = document.getElementById(`chart_${crypto}`);
      if (!chartDiv) return;
      try {
        chartDiv.innerHTML = "";
        new TradingView.widget({
          container_id: `chart_${crypto}`,
          symbol: TRADINGVIEW_SYMBOLS[crypto],
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
          studies: [],
          show_popup_button: true,
          popup_width: "1000",
          popup_height: "650",
        });
      } catch (error) {
        chartDiv.innerHTML = `
          <div style="display:flex;justify-content:center;align-items:center;height:400px;background-color:#1E2029;color:white;border-radius:8px;">
            <div style="text-align:center;padding:20px;">
              <h3>Error al cargar el gráfico</h3>
              <p>Intente recargar la página</p>
            </div>
          </div>
        `;
      }
    });
  }, 500);
}
