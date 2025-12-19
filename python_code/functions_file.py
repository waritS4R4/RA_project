# This is the files for functions used in the simulation
import numpy as np
import matplotlib.pyplot as plt
import python_code.constants_file as cf



# Dynamic voltage and freqeucy scaling (DVFS) model for servers' CPU ref: Vasques et al. 2019
def DVFS_model(C, N_sw, V_dd, f, c0, c1):
    """
    Simple DVFS model to estimate power consumption based on embedded system principles.
    C = circuit capacitance
    N_sw = number of circuit switches per clock cycle
    V_dd = supply voltage of CPU
    f = clock frequency
    """
    P_CPU = C * N_sw * V_dd**2 * f
    P_non_CPU = c0 + c1*f**3 # Non-CPU power consumption (e.g., memory, I/O)

    return P_CPU + P_non_CPU

def utilisation_model(k, l, u, alpha, a, P_STATIC, theta, m_ac):  #Yu and Lai et al. 2019
    """ This is the model constructed in 2006 which probably means it's outdated?
    Utilisation model to estimate power consumption based on CPU utilisation.
    k = kernel number
    """
    p_server = k*(l/u)**alpha*a + P_STATIC
    p = theta*m_ac*p_server
    return p

def utilisation_model_regression(u):  #Beloglazov and Buyya 2010
    """
    Another utilisation model to estimate power consumption based on CPU utilisation.
    u = CPU utilisation (0 to 1)
    P_IDLE = Power consumption at idle state
    P_PEAK = Power consumption at peak state
    """
    global P_IDLE, P_PEAK
    return (P_IDLE + (P_PEAK - P_IDLE) * u)*1e-3  # Convert W to kW


def server_consumption(C_PUE, A, L, L_rate, P_IDLE, P_PEAK):  # Yang et al. 2023 this is per rack (divided by Active servers)
                                                              # https://doi.org/10.1016/j.epsr.2023.109443
    
    """ 
    erver power consumption model considering PUE.
    C_PUE = PUE coefficient
    A = number of active servers
    L = total number of arriving workload 
    L_rate = server service rate (requests per second)"""
    P_DC =  A * (P_IDLE + (C_PUE-1)) + L*(P_PEAK-P_IDLE)/(L_rate)
    return P_DC/1000  # Convert W to kW

# Electrical ESS modelling from Fu et al. 2026
def update_battery_energy(E_bat_prev, eta_loss, eta_ch, epsilon_ch, P_ch, delta_t, epsilon_dis, P_dis, eta_dis):
    """                  
    Updates battery energy for the next time step.

    Parameters:
        E_bat_prev (float): Battery energy at previous time step
        eta_loss (float): Battery loss coefficient (fractional)
        eta_ch (float): Charging efficiency
        epsilon_ch (int): Charging indicator (1 if charging, 0 otherwise)
        P_ch (float): Charging power
        delta_t (float): Time step duration
        epsilon_dis (int): Discharging indicator (1 if discharging, 0 otherwise)
        P_dis (float): Discharging power
        eta_dis (float): Discharging efficiency

    Returns:
        float: Updated battery energy

    Raises:
        ValueError: If both charging and discharging indicators are 1 at the same time.
    """
    # if epsilon_ch + epsilon_dis > 1:
    #     raise ValueError("Battery cannot charge and discharge at the same time (epsilon_ch + epsilon_dis <= 1).")

    E_bat = (1 - eta_loss) * E_bat_prev \
            + eta_ch * epsilon_ch * P_ch * 1e3 * delta_t \
            - (epsilon_dis * P_dis * 1e3 * delta_t) / eta_dis
    
    # E_bat = (1 - eta_loss) * E_bat_prev \
    #         + eta_ch * epsilon_ch * P_ch * delta_t \

    return E_bat #this is SoC


# PV generation model from Fu et al. 2026
def pv_output(eta_invt, P_stc, G, G_stc, gamma, T_cell, T_stc):
    """
    Calculate PV output power under given conditions.

    Parameters:
        eta_invt (float): Inverter efficiency
        P_stc (float): Rated PV power at STC
        G (float): Irradiance (W/m^2)
        G_stc (float): Irradiance at STC (usually 1000 W/m^2)
        gamma (float): Temperature coefficient (%/°C, use fraction, e.g. -0.004)
        T_cell (float): Cell temperature (°C)
        T_stc (float): Cell temperature at STC (usually 25°C)

    Returns:
        float: PV output power
    """
    return eta_invt * P_stc * (G / G_stc) * (1 + gamma * (T_cell - T_stc))* 1e-3  # Convert W to kW

def cell_temperature(T_amb, G, T_NOCT, G_NOCT):
    """
    Calculate cell temperature using the nominal operating cell temperature method.

    Parameters:
        T_amb (float): Ambient temperature (°C)
        G (float): Irradiance (W/m^2)
    Returns:
        float: Cell temperature (°C)
    """
    return T_amb + (G / G_NOCT) * (T_NOCT-T_amb)


# Wind power generation model from power curve of a wind turbine
def wind_power_from_curve(v):
    """
    Calculate wind power output (kW) from wind speed (m/s) using the provided power curve.
    """
    # Power curve data (wind speed in m/s, power in kW)
    wind_speeds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
    power_curve = [0, 5, 10, 18, 27, 38, 51, 65, 80, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100]

    # If below cut-in or above cut-out, power is 0
    if v < cf.V_CUT_IN or v > cf.V_CUT_OUT:
        return 0.0
    # If above rated, return rated power
    elif v >= cf.V_RATED:
        return 100.0
    else:
        # Linear interpolation between points
        for i in range(len(wind_speeds) - 1):
            if wind_speeds[i] <= v < wind_speeds[i + 1]:
                # Interpolate between power_curve[i] and power_curve[i+1]
                p1, p2 = power_curve[i], power_curve[i + 1]
                v1, v2 = wind_speeds[i], wind_speeds[i + 1]
                return p1 + (p2 - p1) * (v - v1) / (v2 - v1)
        # If exactly at the last point
        if v == wind_speeds[-1]:
            return power_curve[-1]
        return 0.0

def fan_qs_piecewise(TI):
    TI = np.asarray(TI)
    return np.where(
        TI <= 27.0, 0.05852,
        np.where(TI < 35.0, 0.05852 + (TI - 27.0)*0.00528, 0.1005)
    )

def waste_heat_recovery(T_in, T_out, Q, RHO_A, CP_A, mode):
    if mode == 'constant':      #fixed TRCU
        T_in = np.array([22.0 for _ in range(len(T_in))])  # fixed inlet temperature
        return [RHO_A * CP_A * Q *(T_out - T_in), T_in]
    elif mode == 'varied':    #adjustable TRCU
        return [RHO_A * CP_A * Q * (T_out - T_in), T_in]  # Example of an alternative calculation
    else:
        raise ValueError("Unknown mode, option: constant or varied")

def cooling_power(H, COP_C, beta_0, beta_1, beta_2, Q_rcu, T):
    """
    Calculate cooling power consumption based on airflow.

    Parameters:
        beta_0 (float): Coefficient for constant term
        beta_1 (float): Coefficient for linear term
        beta_2 (float): Coefficient for quadratic term
        Q_rcu (float): Airflow rate

    Returns:
        float: Cooling power consumption
    """
    COP_C_t = 0.0068*T**2 + 0.0008*T + 0.458  # COP as a function of temperature
    p_source = H/COP_C_t
    p_fan = beta_0 + beta_1 * Q_rcu + beta_2 * Q_rcu**2
    p = p_source + p_fan

    return [p, COP_C_t]

def QoS_function(L_RATE, L_IW, A_DC):
    return 1 / (L_RATE - L_IW / A_DC)

# Plot thermal dynamics of DC model in response to step input
def simulate_discrete_ss(A, B, C, D, Ts, U, x0=None):
    """
    A: (n,n), B: (n,m), C: (p,n), D: (p,m)
    U: (m, N) input sequence
    x0: (n,) initial states
    Returns: t (N,), X (n,N), Y (p,N)
    """
    n, m = B.shape[0], B.shape[1]
    N = U.shape[1]
    p = C.shape[0]

    print("total simulation step",U.shape[1] )

    if x0 is None:
        x = np.zeros(n)
    else:
        x = np.array(x0, dtype=float)

    X = np.zeros((n, N))
    Y = np.zeros((p, N))
    t = np.arange(N) * Ts/60  # time in minutes

    for k in range(N):
        u = U[:, k]
        Y[:, k] = C @ x + D @ u
        x = A @ x + B @ u
        X[:, k] = x

    return t, X, Y


# for data visualisation
# line plot for single time series
def plot_timeseries_multi(t, series_list, labels, title, xlabel="Time step", ylabel="Value", figsize=(8, 4)):
    plt.figure(figsize=figsize)
    for y, label in zip(series_list, labels):
        plt.plot(t, y, label=label)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.show()
    
# bar plot for multiple time series
def plot_bar_multi(t, series_list, labels, title,  xlabel="Time step", ylabel="Value", figsize=(8, 4)):
    x = np.arange(len(t))
    total_width = 0.8
    num_series = len(series_list)
    bar_width = total_width / num_series
    plt.figure(figsize=figsize)
    for i, (y, label) in enumerate(zip(series_list, labels)):
        plt.bar(x + i * bar_width, y, width=bar_width, label=label)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(x + total_width / 2 - bar_width / 2, t)
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.show()
