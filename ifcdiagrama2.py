import numpy as np
import matplotlib.pyplot as plt

# Parámetros físicos
v = 0.8  # Velocidad de la nave O en unidades de c
gamma = 1 / np.sqrt(1 - v**2)  # Factor de Lorentz
L = 10  # Longitud propia de las naves
L_contraida = L / gamma  # Contracción de Lorentz
t_max = 15  # Tiempo máximo para la simulación

# Tiempos y posiciones
t = np.linspace(0, t_max, 200)
x_O_inicio = -v * t
x_O_fin = -L_contraida - v * t  # La nave O se mueve con velocidad -v

# Crear figura más grande
plt.figure(figsize=(8, 8))

# Cono de luz
t_cono = np.linspace(0, t_max, 200)
x_cono_izq = -t_cono
x_cono_der = t_cono
plt.plot(x_cono_izq, t_cono, 'k--', lw=1, alpha=0.6, label='Cono de luz')
plt.plot(x_cono_der, t_cono, 'k--', lw=1, alpha=0.6)

# Líneas de mundo de la nave O (en movimiento)
plt.plot(x_O_inicio, t, 'b-', lw=2, label="Cola de la nave O")
plt.plot(x_O_fin, t, 'b-', lw=2, label="Frente de la nave O")

# Eventos
plt.plot(0, 0, 'ko', label="Coincidencia de a y a'")
plt.text(0, -1, r'$E_1$', ha='center', fontsize=14)

# Configuración del gráfico
plt.xlabel(r"$x'$ (m)", fontsize=14)
plt.ylabel(r"$t'$ (s)", fontsize=14)
plt.title(r"Diagrama Espaciotemporal en $S'$ (Nave O\' en reposo)", fontsize=16)
plt.xlim(-L - 15, 5)
plt.ylim(-2, t_max)
plt.legend(loc='upper left', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)
plt.tight_layout()

# Guardar el gráfico como PDF
plt.savefig('diagrama_nave_Oprime.pdf', dpi=300)
plt.show()
