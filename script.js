// Configuraciones principales
const API_URL = "/api";
const CRYPTOS = ["bitcoin", "ethereum", "dogecoin"];
const TRADINGVIEW_SYMBOLS = {
    bitcoin: "BINANCE:BTCUSDT",
    ethereum: "BINANCE:ETHUSDT",
    dogecoin: "BINANCE:DOGEUSDT"
};

// Aplicación Vue
const app = Vue.createApp({
    data() {
        return {
            showLoginModal: false,
            showRegistroModal: false,
            loginEmail: '',
            loginPassword: '',
            registerName: '',
            registerEmail: '',
            registerPassword: '',
            isLoggedIn: false,
            prices: {
                bitcoin: "Cargando...",
                ethereum: "Cargando...",
                dogecoin: "Cargando..."
            },
            previousPrices: {
                bitcoin: null,
                ethereum: null,
                dogecoin: null
            },
            priceDirections: {
                bitcoin: null,
                ethereum: null,
                dogecoin: null
            },
            userRole: null,
            userId: null,
            activeTab: 'dashboard',
            users: [],
            showCustomAlert: false,
            customAlertMessage: '',
            updateInterval: null,
            lastUpdate: null
        }
    },
    methods: {
        // Método para mostrar alerta personalizada
        showAlert(message) {
            this.customAlertMessage = message;
            this.showCustomAlert = true;
        },

        // Verificar estado de sesión
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
                        "Authorization": `Bearer ${token}`,
                        "Content-Type": "application/json"
                    }
                });

                if (response.ok) {
                    this.isLoggedIn = true;
                    this.fetchCryptoPrices();
                    this.startPriceUpdates();
                    
                    setTimeout(() => {
                        loadTradingViewCharts();
                    }, 1000);
                    
                    if (this.userRole === 'Dueño' || this.userRole === 'Gerente') {
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

        // Iniciar actualizaciones automáticas de precios
        startPriceUpdates() {
            if (this.updateInterval) {
                clearInterval(this.updateInterval);
            }
            
            // Actualizar precios cada 10 segundos
            this.updateInterval = setInterval(() => {
                this.fetchCryptoPrices();
            }, 10000);
        },

        // Detener actualizaciones automáticas
        stopPriceUpdates() {
            if (this.updateInterval) {
                clearInterval(this.updateInterval);
                this.updateInterval = null;
            }
        },

        // Obtener precios actualizados de criptomonedas
        async fetchCryptoPrices() {
            if (!this.isLoggedIn) return;

            try {
                const response = await fetch(`${API_URL}/crypto-prices`);
                const data = await response.json();
                
                if (data.message) {
                    console.warn("CoinGecko respondió con un mensaje:", data.message);
                    return;
                }
                
                // Guardar los precios anteriores antes de actualizar
                this.previousPrices = {
                    bitcoin: this.getNumericPrice(this.prices.bitcoin),
                    ethereum: this.getNumericPrice(this.prices.ethereum),
                    dogecoin: this.getNumericPrice(this.prices.dogecoin)
                };
                
                // Formatear y actualizar a los nuevos precios
                const formattedBitcoin = data.bitcoin.usd.toLocaleString('en-US', { 
                    style: 'currency', 
                    currency: 'USD',
                    minimumFractionDigits: 2,
                    maximumFractionDigits: 2
                });
                
                const formattedEthereum = data.ethereum.usd.toLocaleString('en-US', { 
                    style: 'currency', 
                    currency: 'USD',
                    minimumFractionDigits: 2,
                    maximumFractionDigits: 2
                });
                
                const formattedDogecoin = data.dogecoin.usd.toLocaleString('en-US', { 
                    style: 'currency', 
                    currency: 'USD',
                    minimumFractionDigits: 6,
                    maximumFractionDigits: 6
                });
                
                this.prices.bitcoin = formattedBitcoin;
                this.prices.ethereum = formattedEthereum;
                this.prices.dogecoin = formattedDogecoin;
                
                // Determinar la dirección del cambio de precio
                if (this.previousPrices.bitcoin !== null) {
                    this.priceDirections.bitcoin = data.bitcoin.usd > this.previousPrices.bitcoin ? 'up' : 
                                                 data.bitcoin.usd < this.previousPrices.bitcoin ? 'down' : null;
                    
                    this.priceDirections.ethereum = data.ethereum.usd > this.previousPrices.ethereum ? 'up' : 
                                                  data.ethereum.usd < this.previousPrices.ethereum ? 'down' : null;
                    
                    this.priceDirections.dogecoin = data.dogecoin.usd > this.previousPrices.dogecoin ? 'up' : 
                                                  data.dogecoin.usd < this.previousPrices.dogecoin ? 'down' : null;
                }
                
                // Actualizar timestamp de la última actualización
                this.lastUpdate = new Date();
                
                // Resetear las direcciones de precio después de 2 segundos
                setTimeout(() => {
                    this.priceDirections = {
                        bitcoin: null,
                        ethereum: null,
                        dogecoin: null
                    };
                }, 2000);
                
            } catch (error) {
                console.error("Error obteniendo precios:", error);
            }
        },
        
        // Extraer el valor numérico del precio formateado
        getNumericPrice(formattedPrice) {
            if (formattedPrice === "Cargando...") return null;
            return parseFloat(formattedPrice.replace(/[$,]/g, ''));
        },

        // Iniciar sesión
        login() {
            fetch(`${API_URL}/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                    email: this.loginEmail,
                    password: this.loginPassword 
                })
            })
            .then(response => response.json())
            .then(data => {
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

                    setTimeout(() => {
                        loadTradingViewCharts();
                    }, 1000);
                } else {
                    this.showAlert("Credenciales incorrectas");
                }
            })
            .catch(error => {
                console.error("Error en login:", error);
                this.showAlert("Error de conexión. Intente nuevamente.");
            });
        },
        
        // Registrar nuevo usuario
        register() {
            fetch(`${API_URL}/register`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                    nombre: this.registerName,
                    email: this.registerEmail,
                    password: this.registerPassword 
                })
            })
            .then(response => response.json())
            .then(data => {
                this.showAlert(data.message);
                if (data.id) {
                    this.loginEmail = this.registerEmail;
                    this.loginPassword = this.registerPassword;
                    this.showRegistroModal = false;
                    this.login();
                }
            })
            .catch(error => {
                console.error("Error en registro:", error);
                this.showAlert("Error de conexión. Intente nuevamente.");
            });
        },
        
        // Cerrar sesión
        logout() {
            this.stopPriceUpdates();
            localStorage.removeItem("token");
            localStorage.removeItem("rol");
            localStorage.removeItem("userId");
            this.isLoggedIn = false;
            this.userRole = null;
            this.userId = null;
            this.activeTab = 'dashboard';
        },
        
        // Cargar lista de usuarios
        loadUsers() {
            const token = localStorage.getItem("token");
            
            fetch(`${API_URL}/usuarios`, {
                method: "GET",
                headers: { "Authorization": `Bearer ${token}` }
            })
            .then(response => response.json())
            .then(data => {
                this.users = data;
                
                setTimeout(() => {
                    loadTradingViewCharts();
                }, 1000);
            })
            .catch(error => {
                console.error("Error al cargar usuarios:", error);
                this.showAlert("Error al cargar la lista de usuarios");
            });
        },
        
        // Cambiar rol de usuario
        changeUserRole(userId, currentRole) {
            const token = localStorage.getItem("token");
            let newRole = prompt(`Ingrese el nuevo rol para este usuario (actual: ${currentRole})\nOpciones: Dueño, Gerente, Trabajador, Usuario:`);

            if (!newRole || !["Dueño", "Gerente", "Trabajador", "Usuario"].includes(newRole)) {
                this.showAlert("Rol inválido.");
                return;
            }

            fetch(`${API_URL}/usuarios/${userId}/rol`, {
                method: "PUT",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ rol: newRole })
            })
            .then(response => response.json())
            .then(data => {
                this.showAlert(data.message);
                this.loadUsers();
            })
            .catch(error => {
                console.error("Error al cambiar rol:", error);
                this.showAlert("Error al cambiar el rol");
            });
        },
        
        // Eliminar usuario
        deleteUser(userId) {
            const token = localStorage.getItem("token");

            if (!confirm("¿Estás seguro de eliminar este usuario?")) return;

            fetch(`${API_URL}/usuarios/${userId}`, {
                method: "DELETE",
                headers: { "Authorization": `Bearer ${token}` }
            })
            .then(response => response.json())
            .then(data => {
                this.showAlert(data.message);
                this.loadUsers();
            })
            .catch(error => {
                console.error("Error al eliminar usuario:", error);
                this.showAlert("Error al eliminar usuario");
            });
        }
    },
    mounted() {
        this.checkLoginStatus();
    },
    beforeUnmount() {
        this.stopPriceUpdates();
    }
}).mount('#app');

// Función para cargar gráficos de TradingView
function loadTradingViewCharts() {
    setTimeout(() => {
        CRYPTOS.forEach(crypto => {
            const chartDiv = document.getElementById(`chart_${crypto}`);
            if (chartDiv) {
                try {
                    chartDiv.innerHTML = '';
                    
                    new TradingView.widget({
                        "container_id": `chart_${crypto}`,
                        "symbol": TRADINGVIEW_SYMBOLS[crypto],
                        "interval": "1",
                        "timezone": "Etc/UTC",
                        "theme": "dark",
                        "style": "1",
                        "locale": "es",
                        "toolbar_bg": "#f1f3f6",
                        "enable_publishing": false,
                        "withdateranges": true,
                        "hide_side_toolbar": false,
                        "allow_symbol_change": true,
                        "save_image": false,
                        "width": "100%",
                        "height": 400,
                        "autosize": false,
                        "hide_volume": false,
                        "studies": [],
                        "show_popup_button": true,
                        "popup_width": "1000",
                        "popup_height": "650"
                    });
                } catch (error) {
                    chartDiv.innerHTML = `
                        <div style="display: flex; justify-content: center; align-items: center; height: 400px; background-color: #1E2029; color: white; border-radius: 8px;">
                            <div style="text-align: center; padding: 20px;">
                                <h3>Error al cargar el gráfico</h3>
                                <p>Intente recargar la página</p>
                            </div>
                        </div>
                    `;
                }
            }
        });
    }, 500);
}