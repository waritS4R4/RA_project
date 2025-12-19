# %%
# import the neccessary libraries
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt

import pandas as pd
import gurobipy as gp
from gurobipy import Model, GRB, quicksum
from scipy.signal import cont2discrete
import pvlib
from control import ss, c2d
from vpp_ward import openmeteo, renewable_assets

# import constants
import python_code.functions_file as ff
import python_code.constants_file as cf
import Monitored_file as mf


# %%
# ------------------------ Data centre thermal model--------------------------
# Version 2: Linear SS from control-oriented model paper by Wang et al. 2025
# Obtain the model from PEM file
#from PEM import A,B,C,D,state_offset

# Use the same model from the dissertation ( equivalent 2 servers in a racks)
# System's complete state-space model
# Define constants (replace with actual values)
def initialise():
    # global variables
    global A, B, C, D, L_BW_0, L_max, P_solar, P_wind, heat_demand, p_buy, p_sell, p_gas, X0, U0
    global A_5min, B_5min, C_5min, D_5min

    Ts_hour = 60*60;  # sampling time in 1 cf.HOURS 
    Ts_5min = 5*60; # sampling time of 5 min for second stage

    RHO_A = 1.2;            # [kg/m^3], air density
    CP_A = 1005;            # [J/kg°C], specific heat of air
    T0 = 22;                # The initial THPCU
    Q0 = 0.02;              # Initial airflow (QHPCU) TEST

    # Coefficients from energy and mass balances scenario 2
    F1 = 0.06; F2 = 0.06;                  # Leakage coefficients (ignored if no leakage)
    Q_s1 = 0.01415*5; Q_s2 = 0.01415*5;    # Under safe operating as range T<25 c, lumping 5 servers into two large server
    Q_L = (Q_s1+Q_s2) - Q0;                # Leakage air assumed zero
    E1 = 0.05; E2 = 0.05;               # Recirculation fractions
    D1 = 0.5; D2 = 0.5;                 # HPCU effectiveness which sum should be equal to 1
    Q_OC1 = D1*Q0+E1*Q_L-F1*Q_L-Q_s1   
    Q_OC2 = D2*Q0+E2*Q_L-F2*Q_L-Q_s2 

    # battery parameter
    eta = 0.95; dt = 1*Ts_hour; E_ESS = 50e6; #13.88 kWh (because 10 servers of 300 W for 10 mins backup ~ 300*10*10*60*60 ~ 108e6
    sigma = 0.001; 

    # === Define System Parameters ====================
    # Define A matrix
    a11 = (-(F1 * abs(Q_L) + Q_s1 + Q_OC1)) / cf.V_I
    a13 = (E1 * abs(Q_L)) / cf.V_I
    a12 = 0; #assuming no zonal leakage
    a21 = 0; #assuming no zonal leakage
    a22 = (-(F2 * abs(Q_L) + Q_s2 + Q_OC2)) / cf.V_I
    a24 = (E2 * abs(Q_L)) / cf.V_I
    a31 = Q_s1 * RHO_A * CP_A / cf.X
    a33 = -Q_s1 * RHO_A * CP_A / cf.X
    a42 = Q_s2 * RHO_A * CP_A / cf.X
    a44 = -Q_s2 * RHO_A * CP_A / cf.X

    # matrix B elements
    b11 = D1*Q0/(cf.V_I*CP_A*RHO_A)
    b12 = D1*T0/(cf.V_I*CP_A*RHO_A)
    b21 = D2*Q0/(cf.V_I*CP_A*RHO_A)
    b22 = D2*T0/(cf.V_I*CP_A*RHO_A)
    b33 = 1 / cf.X
    b44 = 1 / cf.X

    # === State Matrix A (4x4) ===
    A_c = np.array([
        [a11, a12, a13, 0],
        [a21, a22, 0,   a24],
        [a31, 0,   a33, 0],
        [0,   a42, 0,   a44]
    ])

    # === Input Matrix B (4x4) ===
    B_c = np.array([
        [b11, b12, 0, 0],
        [b21, b22, 0, 0],
        [0, 0, b33, 0],
        [0, 0, 0, b44]
    ])

    # === Output Matrix C (2x4) ===
    # Define parameters for output model
    N = 2           # Number of servers / racks
    QHPCU_OP = Q0   # Operating point for Q_HPCU
    k_rho = RHO_A * CP_A  # Heat transfer coefficient
    Tbar = (cf.TO_10 + cf.TO_20) / 2  # Average T outlet
    THPCU_OP = T0   # Operating point of THPCU
    COP_C = 3.5     # Cooling COP
 

    # === Linearisation of waste heat recovery ===
    H_0 = QHPCU_OP * k_rho * (Tbar - THPCU_OP)
    alpha = k_rho * ((Tbar - THPCU_OP) * (-QHPCU_OP)
                    - QHPCU_OP * (-THPCU_OP)
                    + QHPCU_OP * (-Tbar))
    H_est = H_0 + alpha

    # === Fan cooling power coefficients and power estimation ===
    c1 = cf.BETA_0 * QHPCU_OP + cf.BETA_1 * QHPCU_OP**2 + cf.BETA_2 * QHPCU_OP**3
    c2 = cf.BETA_0 + 2 * cf.BETA_1 * QHPCU_OP + 3 * cf.BETA_2 * QHPCU_OP**2

    P_fan0 = c1 - c2 * Q0 + H_est / cf.COP_C  # offset of cooling fan power

    # === Output Matrix C (2x4) ===
    C_c = np.array([
        [0, 0, k_rho * QHPCU_OP / N, k_rho * QHPCU_OP / N],
        [0, 0, (k_rho * QHPCU_OP / N) * (1 / cf.COP_C + 0 * 1 / cf.COP_HP),
            (k_rho * QHPCU_OP / N) * (1 / cf.COP_C + 0 * 1 / cf.COP_HP)]
    ])

    # === Direct feedthrough Matrix D (2x4) ===
    D_c = np.array([
        [-k_rho * QHPCU_OP, k_rho * (Tbar - THPCU_OP), 0, 0],
        [-k_rho * QHPCU_OP * (1 / cf.COP_C + 0 * 1 / cf.COP_HP),
        (c2 + k_rho * (Tbar - THPCU_OP) * (1 / cf.COP_C + 0 * 1 / cf.COP_HP)),
        1, 1]
    ])

    # === Continuous-time system ===
    sys_c = ss(A_c, B_c, C_c, D_c)

    # === Discretised SS (zero-order hold) ===
    sys_dis = c2d(sys_c, Ts_hour, method='zoh')

    A_dis = sys_dis.A
    B_dis = sys_dis.B
    C_dis = sys_dis.C
    D_dis = sys_dis.D

    # check for stability
    eigenvalues = np.linalg.eigvals(A_dis)
    print("Eigenvalues of the discrete system:", eigenvalues)
    if np.all(np.abs(eigenvalues) < 1):
        print("The discrete-time system (A_dis) is stable.")
    else:
        print("The discrete-time system (A_dis) is unstable.")

    # Rename the matrices
    A = A_dis
    B = B_dis
    C = C_dis
    D = D_dis

    # matric for second stage
    # === Discretised SS (zero-order hold) ===
    sys_dis_5min = c2d(sys_c, Ts_5min, method='zoh')
    A_5min = sys_dis_5min.A
    B_5min = sys_dis_5min.B
    C_5min = sys_dis_5min.C
    D_5min = sys_dis_5min.D

    # === Combine discrete thermal dynamics with SoC and Pexe equations ===
    Nstate = 6
    Ninput = 7
    Noutput = 13
    Ndis = 2

    A_d = np.block([
        [A_dis, np.zeros((A_dis.shape[0], Nstate - A_dis.shape[1]))],
        [np.zeros((1, A_dis.shape[1])), np.array([[1 - sigma, 0]])],
        [np.zeros((1, Nstate - 1)), np.array([[1]])]
    ])

    # === Input matrix before adding disturbances ===
    B_d_1 = np.block([
        [B_dis, np.zeros((B_dis.shape[0], Ninput - Ndis - B_dis.shape[1]))],
        [np.zeros((1, B_dis.shape[1])), np.array([[eta * dt / E_ESS]])],
        [np.array([[0, 0, -1, -1, 0]])]
    ])

    # === Input disturbance coefficient matrix ===
    E_d = np.block([
        [np.zeros((Ninput - Ndis, Ndis))],
        [np.array([[1, 0]])]
    ])

    # === Augmented B_d including disturbance ===
    B_d = np.hstack((B_d_1, E_d))

    # === Augmented C matrix ===
    C_d = np.block([
        [C_dis, np.zeros((2, 2))],
        [np.eye(A_d.shape[1])],
        [np.zeros((Ninput - Ndis, Nstate))]
    ])

    # === D matrix before adding disturbance ===
    D_d_1 = np.block([
        [D_dis, np.array([[0], [1]])],
        [np.zeros((Nstate, Ninput - Ndis))],
        [np.eye(Ninput - Ndis)]
    ])

    # === Output disturbance coefficient matrix ===
    F_d = np.block([
        [np.zeros((Noutput, 1)), np.vstack(([0], [-1], np.zeros((Noutput - Ndis, 1))))]
    ])

    # === Augmented D_d including output disturbance ===
    D_d = np.hstack((D_d_1, F_d))

    # === Save to file ===
    from scipy.io import savemat
    savemat('data_center_ss_matrices.mat', {'A_d': A_d, 'B_d': B_d, 'C_d': C_d, 'D_d': D_d})

    # === Discrete-time SS model ===
    sys_d = ss(A_d, B_d, C_d, D_d, Ts_hour)

    print("System defined and saved for Simulink.")

    # === Check system stability ===
    print("Eigenvalues of continuous system:", np.linalg.eigvals(A_c))
    print("Eigenvalues of discrete system:", np.linalg.eigvals(A_dis))
    print("Eigenvalues of augmented system:", np.linalg.eigvals(A_d))

    if np.all(np.abs(np.linalg.eigvals(A_dis)) < 1):
        print("The discrete-time system is stable.")
    else:
        print("The discrete-time system is unstable.") 

    # save matrix elements to text file
    np.savetxt('A_d_matrix.txt', A_d, fmt='%.6f')
    np.savetxt('B_d_matrix.txt', B_d, fmt='%.6f')
    np.savetxt('C_d_matrix.txt', C_d, fmt='%.6f')
    np.savetxt('D_d_matrix.txt', D_d, fmt='%.6f')

    # export matrices
    np.savetxt('A_matrix.txt', A, fmt='%.6f')
    np.savetxt('B_matrix.txt', B, fmt='%.6f')
    np.savetxt('C_matrix.txt', C, fmt='%.6f')
    np.savetxt('D_matrix.txt', D, fmt='%.6f')


    # %%
    # --- Build a step input sequence ---
    Nsteps = 50                 # number of simulation steps
    step_at = [5, 10, 15, 20, 25, 30]       # step time index
    amp = 500                    # step amplitude (units of the chosen input)

    m = B.shape[1]               # number of inputs

    # initial inputs
    Usim = np.zeros((m, Nsteps))
    Usim[0, :] = cf.TRCU_0 # cosntant liquid temperature
    Usim[1, :] = cf.QRCU_0 # constant liquid flows
    # U[2, :] and U[3, :] are already zero

    # Choose which input to step (0=Th, 1=Qh, 2=Ps1, 3=Ps2).
    inp_idx = 2                  # increase server power consumption
    for j in range (len(step_at)):
        Usim[inp_idx, step_at[j]:] += amp
        Usim[inp_idx + 1, step_at[j]:] += amp  # step both servers

    # Nonzero initial state
    x0 = [cf.TI_10, cf.TI_20, cf.TO_10, cf.TO_20]

    # --- Run simulation ---------------
    t, X, Y = ff.simulate_discrete_ss(A, B, C, D, Ts_hour, Usim, x0=x0)

    # --- Plot states (temperatures) ---
    plt.figure()
    labels_x = ["Ti1", "Ti2", "To1", "To2"]
    for i in range(X.shape[0]):
        plt.plot(t, X[i, :], label=labels_x[i], linestyle=':' if (i==0 or i==2) else '-')
    for i in range(len(step_at)):
        plt.axvline(step_at[i] * Ts_hour/60, linestyle="--")  # show step time
    plt.xlabel("Time [min]")
    plt.ylabel("Temperature [°C]")
    plt.title(f"State response to step in input u[{inp_idx}]")
    plt.legend()
    plt.grid(True)
    plt.show()

    # Plot outputs to see H, P, etc. ---
    plt.figure()
    for i in range(Y.shape[0]):
        plt.plot(t, Y[i, :], label=f"y{i+1}")
    for i in range(len(step_at)):
        plt.axvline(step_at[i] * Ts_hour/60, linestyle="--")
    plt.xlabel("Time [min]")
    plt.ylabel("Outputs")
    plt.title("Output response")
    plt.legend(["Heat (W)", "Consumption (W)"])
    plt.grid(True)
    plt.show()


    # %%
    #------------------------ Solar PV model--------------------------
    # estimate solar power generation using PVLib
    # Define location (London)
    latitude = 51.5074
    longitude = -0.1278
    tz = 'Europe/London'
    altitude = 35

    P_solar_days = 1        # Solar generation period in days
    site = pvlib.location.Location(latitude, longitude, tz=tz, altitude=altitude) # Create a location object
    times = pd.date_range('2022-01-01', '2022-12-31 23:00', freq='1H', tz=tz)     # Time range 
    cs = site.get_clearsky(times, model='ineichen')                               # Get clear-sky irradiance (Ineichen model)
    # G = cs['ghi'].values                                                 # GHI in W/m^2 for 1 day and 1 hour interval
    df_gen1hr = pd.read_csv('ghi_1hr_1jan2022.csv') # read ghi data from solcast
    G = df_gen1hr['ghi'].values
    air_temp = df_gen1hr['air_temp'].values

    # Arrays to store results of solar generation
    P_solar = np.zeros(len(G))  # Solar power output
    T_cell = np.zeros(len(G))  # Cell temperature

    for i in range(len(G)):
        T_cell[i] = ff.cell_temperature(air_temp[i], G[i], cf.T_NOCT, cf.G_NOCT)  # Cell temperature
        P_solar[i] = ff.pv_output(cf.ETA_INVT, cf.P_STC, G[i], cf.G_STC, cf.GAMMA, T_cell[i], cf.T_STC)


    # %%
    # Length of plotting data
    length = cf.HOURS*P_solar_days # 7 days of data

    # titles
    ttl_base = f"London — day {mf.CURRENT_DAY} from hour {mf.CURRENT_HOUR} for {length//24} days"
    t_hr  = np.arange(length)  

    print("len t_hr ",len(t_hr))
    print("len T_cell ",len(T_cell[mf.CURRENT_HOUR:mf.CURRENT_HOUR+length]))
    print("length ",length)


    # import weather data from Open-Meteo through vpp ward package
    weather = openmeteo(latitude='51.5074', longitude='-0.1278', start_date='2022-01-01', end_date='2022-12-31', fields=["temperature_2m", "windspeed_100m", "shortwave_radiation"])

    # (1) Temperatures (two lines, one figure)
    ff.plot_timeseries_multi(
        t_hr, [weather['temperature_2m'][mf.CURRENT_HOUR:mf.CURRENT_HOUR+length], T_cell[0:length]], ["Ambient Temp (open meteo)", "T Cell Temp (solcast)"],
        title=f"Ambient & Cell Temperature — {ttl_base}",
        ylabel="°C", xlabel="Hour"
    )

    # (2) Irradiance (single line, one figure)
    ff.plot_timeseries_multi(
        t_hr, [G[0:+length]], ["GHI"],
        title=f"Clear-Sky Irradiance — {ttl_base}",
        ylabel="W/m²", xlabel="Hour"
    )

    # (3) Solar power (single line, one figure)
    P_solar = (P_solar[0:length]) # times by 5 to make it compaible to other power inputs
    ff.plot_timeseries_multi(
        t_hr, [P_solar], ["Estimated Solar Power"],
        title=f"Estimated Solar Power Output — {ttl_base}",
        ylabel="kW", xlabel="Hour"
    )

    wind_speeds = weather['windspeed_100m'].values # use data from open-meteo

    # Plot wind power generation 
    P_wind = np.array([ff.wind_power_from_curve(v) for v in wind_speeds])
    ff.plot_timeseries_multi(
        t_hr, [P_wind[mf.CURRENT_HOUR:mf.CURRENT_HOUR+length],wind_speeds[mf.CURRENT_HOUR:mf.CURRENT_HOUR+length]], ['Wind Power (kW)', 'Wind Speed (m/s)'],
        title=f"Estimated Wind Power Output {mf.CURRENT_DAY}th day from {mf.CURRENT_HOUR}th hour for {length//24} days",
        ylabel="Power (kW)", xlabel="Hour"
    )


    # %%
    #---------------------------Load simulation data---------------------------
    # Heat demand from neighbouring thermal users
    heat_demand_data = pd.read_csv('Renaldi_AppliedEnergy_Heat_Demand_Data.csv')
    heat_demand = heat_demand_data['Heat demand (kW)'].values[:24]

    # Price data for buying and selling electricity from a csv file
    price_data = pd.read_csv('prices_data.csv')
    p_buy  = price_data['elec_price'].values
    p_sell = price_data['elec_price_sell'].values
    p_gas  = price_data['gas_price'].values

    # Example of computing load profile for dc power consumption and batch workload
    L_BW_0 =  mf.L_DC - mf.L_IW  # exact batch workload at each time step
    P_DC = ff.server_consumption(cf.c_pue, 1, mf.L_DC, cf.L_RATE, cf.P_IDLE, cf.P_PEAK)
    P_IW = ff.server_consumption(cf.c_pue, 1, mf.L_IW, cf.L_RATE, cf.P_IDLE, cf.P_PEAK)
    P_BW = ff.server_consumption(cf.c_pue, 1, L_BW_0, cf.L_RATE, cf.P_IDLE, cf.P_PEAK)

    # Plots the inputs 
    fig, ax1 = plt.subplots(figsize=(10, 4))

    # --- Primary y-axis ---
    ax1.plot(heat_demand, label='Heat Demand (kW)', color='tab:red')
    ax1.plot(P_solar[mf.CURRENT_HOUR:mf.CURRENT_HOUR+length],
            label='Solar Power Generation (kW)', color='tab:orange')
    ax1.plot(P_wind[mf.CURRENT_HOUR:mf.CURRENT_HOUR+length],
            label='Wind Power Generation (kW)', color='tab:blue')

    ax1.set_xlabel('Hour')
    ax1.set_ylabel('Thermal / Renewable Power (kW)', color='tab:red')
    ax1.tick_params(axis='y', labelcolor='tab:red')
    ax1.grid(True)

    # --- Secondary y-axis (for data centre power) ---
    ax2 = ax1.twinx()
    ax2.plot(P_DC, label='Data Centre Power Demand (kW)', color='tab:purple', linewidth=2)
    ax2.plot(P_IW, label='Interactive Workload Power (kW)', color='tab:green', linestyle='--')
    ax2.plot(P_BW, label='Batch Workload Power (kW)', color='tab:brown', linestyle=':')
    ax2.set_ylabel('Computing Request (kW)', color='tab:purple')
    ax2.tick_params(axis='y', labelcolor='tab:purple')

    # --- Combine legends --------
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', bbox_to_anchor=(1, 1))

    plt.title('Input Data for Optimisation')
    plt.tight_layout()
    plt.show()

    # Table of the main parameters
    Total_L_BW = np.sum(L_BW_0)
    Avg_hourly_L_BW = Total_L_BW/cf.HOURS
    L_max = np.max(mf.L_IW) + Avg_hourly_L_BW
    PS_avg_max = ff.server_consumption(cf.c_pue, 1, L_max, cf.L_RATE, cf.P_IDLE, cf.P_PEAK) 

    # ploting original power consumption
    print("Total Batch Workload (FLOPH):", Total_L_BW)
    print("Average Batch Workload (FLOPH):", round(Avg_hourly_L_BW,4))
    print("Data Centre Anticipated Maximum Server Consumption (kW):", round(PS_avg_max,4)) # this shouldnt be greater than server max power

    # export this generation and heat demand to CSV for the next stage
    generation_data = pd.DataFrame({
        'Solar_Power_kW': P_solar,
        'Wind_Power_kW': P_wind[mf.CURRENT_HOUR:mf.CURRENT_HOUR+length],
        'Heat_Demand_kW': heat_demand  # original heat demand data
    })
    generation_data.to_csv('generation_and_heat_demand_data.csv', index=False)  


    # %%
    # Upper layer optimisation for day-ahead scheduling of data centre with solar and battery storage
    #------------------------ Gurobi Optimisation--------------------------
    global options, T, delta_t, mode
    options = {                 # Retrieve Gurobi licence
        "WLSACCESSID": "ee9bea66-ab05-406d-91a7-20582d51dfd6",
        "WLSSECRET": "5d1f81b2-4889-49d3-a1a2-796de424605a",
        "LICENSEID": 2712303,
    }
        
    # Data (arrays of length T)
    T = len(p_buy)          # p_buy[t], p_sell[t]
    delta_t = 60*60            # 1 hr interval for power cost because ( price is in $/kWh )

    # Constraints:
    """constraints:
    1. Power balance constraint
    2. Battery operational constraints
    3. Solar power generation constraints
    4. Temperature constraints
    5. Cooling power constraints
    6. Computing load constraints"""


    # check that the  bounds are feasible
    assert (cf.Ps_max)*cf.HOURS >= np.sum(ff.server_consumption(cf.c_pue, 1, mf.L_DC, cf.L_RATE, cf.P_IDLE, cf.P_PEAK)), "Server power max limit too low for the IW+BW workload"


    # %%
    # Initial conditions for each variables
    TI_0 = np.full(2,  cf.TI_10)   # initial inlet temp for all servers
    TO_0 = np.full(2,  cf.TO_10)   # initial outlet temp for all servers
    X0 = np.concatenate([TI_0,  TO_0])          # shape (20,) for 10 servers

    TRCU_0_arr = np.full(1,  cf.TRCU_0)  # initial cold air supply temperature for single RCU per rack
    QRCU_0_arr = np.full(1,  cf.QRCU_0)  # initial airflow for single RCU
    PS_0_arr = np.full(N,  cf.PS_0)  # initial server power for all servers
    U0 = np.concatenate([TRCU_0_arr, QRCU_0_arr, PS_0_arr])

    global mode
        # Objective types: take users value to determine the types of objective function
    user_choice = input("Select objective type:\n0 - Single objective\n1 - Multi-objective with heat tracking penalty\nEnter 0 or 1: ")
    if user_choice == "0":
        mode = 0  # Single objective
        print(f"Objective type selected: Single objective")
    elif user_choice == "1":
        mode = 1  # Multi-objective with heat tracking penalty
        print(f"Objective type selected: Multi-objective")
    else:
        print("Invalid choice, defaulting to single objective.")
        mode = 0

def main():
    # Declare waste heat variables
    # avg_TO = 0; avg_TRCU = 0

    # Decision vars
    # state variables
    with gp.Env(params=options) as env:
        m = gp.Model("Upper_Layer_Optimisation", env=env)

        # state variables
        lb_X = np.array([ cf.Ti_min]*cf.NUMBER_OF_SERVERS  + [ cf.To_min]*cf.NUMBER_OF_SERVERS)
        ub_X = np.array([ cf.Ti_max]*cf.NUMBER_OF_SERVERS  + [ cf.To_max]*cf.NUMBER_OF_SERVERS)
        #X  = m.addMVar((3*cf.NUMBER_OF_SERVERS, cf.HOURS), lb=lb_X[:, None], ub=ub_X[:, None], name="X")
        X_1  = m.addMVar((2*2, cf.HOURS), name="rack 1")

        # Group server power into an input list
        lb_U = np.array([cf.TRCU_min, cf.QRCU_min, cf.Ps_min, cf.Ps_min])  # For 2 servers
        ub_U = np.array([cf.TRCU_max, cf.QRCU_max, cf.Ps_max, cf.Ps_max])  # For 2 servers
        # U = m.addMVar((4, cf.HOURS), lb=lb_U[:, None], ub=ub_U[:, None], name="U")  # Control variables
        U = m.addMVar((4, cf.HOURS), lb=np.tile(lb_U[:, None], (1, cf.HOURS)), ub=np.tile(ub_U[:, None], (1, cf.HOURS)), name="U")  # Control variables

        L_BW = m.addMVar((cf.NUMBER_OF_SERVERS, cf.HOURS), lb=0, ub=L_max, name="L_BW")  # Data centre load
        A_DC = m.addMVar((cf.HOURS), lb=0, ub=10,     name="A_DC")  # number of active server
        L    = m.addVars(cf.HOURS, name="L")          # total load
        P_dc = m.addVars(cf.HOURS, name="P_dc")       # data centre power
        total_previous_LBW = m.addVars(cf.HOURS, name="previous_LBW")       # BW scheduled before time t
        
        SoC  = m.addMVar(cf.HOURS, lb=cf.SoC_min, ub=cf.SoC_max, name="SoC")   # Battery SoC
        H_sub = m.addMVar(T, name="H_sub")  # Auxiliary, no explicit bounds
        H_1   = m.addMVar(cf.HOURS, lb=0, name="H_1")                          # Heat extracted 

        Pimp = m.addMVar(cf.HOURS,  lb=0, ub = cf.Pg_max, name="Pimp")  # Grid import (≥0)
        Pexp = m.addMVar(cf.HOURS, lb=0, ub = cf.Pg_max, name="Pexp")  # Grid export (≥0)
        Pch  = m.addMVar(cf.HOURS, lb=0,     ub=cf.Pbat_max, name="Pch") # Battery charge (≥0)
        Pdis = m.addMVar(cf.HOURS, lb=0,     ub=cf.Pbat_max, name="Pdis")# Battery discharge (≥0)
        epsilon_ch = m.addMVar(cf.HOURS, vtype=GRB.BINARY, name="epsilon_ch") # Charge indicator
        epsilon_dis = m.addMVar(cf.HOURS, vtype=GRB.BINARY, name="epsilon_dis") # Discharge indicator
        P_source = m.addMVar(cf.HOURS,  name="P_source")  # Cooling source power
        P_fan    = m.addMVar(cf.HOURS,  name="P_fan")       # Cooling fan power
        P_cooling = m.addMVar(cf.HOURS,  name="P_cooling") # Total cooling power
        avg_TRCU = m.addMVar(cf.HOURS,  name="Avg_TRCU") # Average cooling liuid incoming temperature
        avg_TO = m.addMVar(cf.HOURS,  name="Avg_T0") # Average outlet zone temperature

        # initial conditions of previously determined variables at t = 0
        m.addConstr(X_1[:, 0] == X0, name="initial_states_X_1") # Initial condition for temperatures states
        m.addConstr(SoC[0] == cf.SoC_0, name="initial_states_SoC")  # Initial condition for battery SoC
        m.addConstr(U[:, 0] == U0, name="initial_inputs_U_0")          # Initial condition for control inputs
        m.addConstr(total_previous_LBW[0] == 0, name="initial_total_schedule_BW")          # Initial condition for control inputs
        m.addConstr(L_BW[:,0] == np.zeros(cf.NUMBER_OF_SERVERS))

        # total load and data centre power consumption constraints
        for t in range(cf.HOURS):
            m.addConstr(
            L[t] == quicksum(L_BW[j, t] for j in range(cf.NUMBER_OF_SERVERS)) + mf.L_IW[t],name=f"total_load_{t}"
            )
            
            # P_dc_expr = ff.server_consumption(cf.c_pue, 1, L[t], cf.L_RATE, cf.P_IDLE, cf.P_PEAK)  # must return a LinExpr
            m.addConstr(P_dc[t] == (A_DC[t] * (cf.P_IDLE + (cf.c_pue-1)) + L[t]*(cf.P_PEAK-cf.P_IDLE)/(cf.L_RATE))/1e3, name=f"pdc_def_{t}")
        
        cum_arrival = 0
        cum_scheduled = 0

        for t in range(cf.HOURS):
            # update cumulative arrivals (data, not decision vars)
            cum_arrival += L_BW_0[t]

            # update cumulative scheduled (decision vars)
            cum_scheduled += quicksum(L_BW[j, t] for j in range(cf.NUMBER_OF_SERVERS))

            # cannot have scheduled more than has arrived up to time t
            m.addConstr(
                cum_scheduled <= cum_arrival,
                name=f"cumulative_batch_feasibility_{t}")

            # Sufficinet active servers for batch workload
            m.addConstr(cf.L_RATE*A_DC[t] >= quicksum(L_BW[i][t] for i in range(cf.NUMBER_OF_SERVERS)), name=f"active_server_for_BW")

        #End of day workload, all of the schedule workload must be executed within a day
        m.addConstr(quicksum(L_BW[j,t] for j in range(cf.NUMBER_OF_SERVERS) for t in range(cf.HOURS)) == quicksum(L_BW_0[t] for t in range(cf.HOURS)), name="end_of_day_workload")

        # Constraints for QoS: limited time delay for batch workload
        for t in range(1,cf.HOURS):
            m.addConstr(A_DC[t]*cf.L_RATE - mf.L_IW[t] >= 0, name=f"A_DC_{t}")
            m.addConstr(A_DC[t]*(cf.L_RATE - 1/cf.MAX_DELAY) - mf.L_IW[t] <= 0, name=f"qos_delay_{t}")

        # Update temperature dynamics using discretized state-space model
        for t in range(1, cf.HOURS):  # start from 1 to avoid negative index

            # Server power consumption constraints based on current load and cooling conditions
            m.addConstr(
                U[2, t-1] == ff.server_consumption(1.5, A_DC[t-1], L_BW[0, t]+mf.L_IW[t-1]/2, cf.L_RATE, cf.P_IDLE, cf.P_PEAK)*1000, name=f"PS1_{t}" # convert to W
            )

            m.addConstr(
                U[3, t-1] == ff.server_consumption(1.5, A_DC[t-1], L_BW[1, t]+mf.L_IW[t-1]/2, cf.L_RATE, cf.P_IDLE, cf.P_PEAK)*1000, name=f"PS2_{t}" # convert to W
            )

            m.addConstr(
                # Compute server power from A and L using the matrix derived from the rack based model
                X_1[:, t] == A @ X_1[:, t-1] + B @ U[:, t-1], name=f"temp_dynamics_X_1_{t}"
            )

            m.addConstr(
                avg_TRCU == U[1, t], name=f"avg_TRCU_{t}"
            )

            avg_TO = (X_1[2, t] + X_1[3, t]) / 2
            dT = avg_TO - avg_TRCU

            # Original H
            m.addConstr(H_1[t] == cf.RHO_A * cf.CP_A * U[1,t] * (avg_TO - U[0,t]), name=f"waste_heat_recovery_{t}")  # Waste heat recovery

            # Cooling power based on COP
            m.addConstr(P_source[t] == H_1[t] / cf.COP_C, name=f"cooling_power_{t}")  
            m.addConstr(P_fan[t] == cf.BETA_0 + cf.BETA_1*U[1, t] + cf.BETA_2*U[1, t]**2, name=f"fan_power_{t}")
            m.addConstr(P_cooling[t] == P_source[t] + P_fan[t], name=f"total_cooling_power_{t}")
        
        
        # constraints for final value of SoC to be equal to initial value
        m.addConstr(SoC[cf.HOURS-1] == cf.SoC_0, name="final_SoC_equals_initial")

        # Power and heat balance constraints
        for t in range(0,cf.HOURS):

            # Power balance constraint
            Pdc_expr = ff.server_consumption(1.5, A_DC[t], L[t], cf.L_RATE, cf.P_IDLE, cf.P_PEAK)
            m.addConstr(
                Pimp[t] - Pexp[t] +  Pdis[t] - Pch[t] + P_solar[t] - P_cooling[t]*1e-3 - Pdc_expr == 0,
                name=f"power_balance_{t}"
            )

            M = cf.Pbat_max
            m.addConstr(Pdis[t] <= M * epsilon_dis[t], name=f"discharge_power_limit_{t}")
            m.addConstr(Pch[t]  <= M * epsilon_ch[t], name=f"charge_power_limit_{t}")
            m.addConstr(epsilon_dis[t] + epsilon_ch[t] <= 1, name=f"battery_state_{t}")
            
            # SoC update constraint
            # m.addConstr(SoC[t] == update_battery_energy(SoC[t-1], cf.ETA_LOSS, cf.ETA_CH, epsilon_ch[t], Pch[t], delta_t, epsilon_dis[t], Pdis[t], cf.ETA_DCH), name=f"battery_dynamics_{t}")
            m.addConstr(
                SoC[t] == (1-cf.ETA_LOSS)*SoC[t-1]
                    + cf.ETA_CH * Pch[t] * 1e3 * delta_t/cf.E_ESS
                    - (1/cf.ETA_DCH) * Pdis[t] * 1e3 * delta_t/cf.E_ESS,
                name=f"SoC_{t}"
            )

            # Heat balance
            m.addConstr(H_sub[t] == heat_demand[t]*1e3 - H_1[t], name=f"heat_balance_{t}")   # here H_saub is in kW
            
        # Declare objective function
        obj = 0

        # Linear energy cost part (exactly equals your abs-based expression)
        obj += quicksum((p_buy[t] * Pimp[t] - p_sell[t] * Pexp[t]) for t in range(cf.HOURS))

        # Cost for substituting heat with gas boiler when waste heat is insufficient:
        # A * delta_t * sum( gas_price[t] * (heat_demand[t] - H[t])^2 )
        obj += quicksum(mode *p_gas[t] * (H_sub[t]*1e-3) + (1-mode) *p_gas[t] * (heat_demand[t]) for t in range(cf.HOURS))

        m.setObjective(obj, GRB.MINIMIZE)
        m.setParam("InfUnbdInfo", 1)  # Distinguish infeasible/unbounded
        m.optimize()

        if m.Status == GRB.INFEASIBLE:
            print("Model infeasible -> computing IIS...")
            m.computeIIS()

            # Write files you can open in a text editor
            m.write("model_stg1.lp")      # full model in LP format
            m.write("infeasible_stg1.ilp")  # IIS in ILP format (minimal conflicting set)

            # List constraints and variable bounds that participate in the IIS
            for c in m.getConstrs():
                if c.IISConstr:
                    print(f"Infeasible constraint: {c.ConstrName}")

            for qc in m.getQConstrs():
                if qc.IISQConstr:
                    print(f"Infeasible quadratic constraint: {qc.QCName}")

            for gc in m.getGenConstrs():
                if gc.IISGenConstr:
                    print(f"Infeasible general constraint: {gc.GenConstrName}")

            for v in m.getVars():
                if v.IISLB:
                    print(f"Infeasible lower bound: {v.VarName} >= {v.LB}")
                if v.IISUB:
                    print(f"Infeasible upper bound: {v.VarName} <= {v.UB}")
            raise RuntimeError(f"Optimization stopped with status {m.Status} (INFEASIBLE). See infeasible.ilp for details.")
        elif m.Status == GRB.UNBOUNDED:
            print("Model is unbounded. Please check your constraints and variable bounds.")
            raise RuntimeError(f"Optimization stopped with status {m.Status} (UNBOUNDED).")
        elif m.Status == GRB.INF_OR_UNBD:
            print("Model is infeasible or unbounded. Please check your model formulation.")
            raise RuntimeError(f"Optimization stopped with status {m.Status} (INF_OR_UNBD).")
        elif m.Status != GRB.OPTIMAL:
            print(f"Optimization stopped with status {m.Status}.")
            raise RuntimeError(f"Optimization stopped with status {m.Status}")
            # Extract solution
        
        # make solution global so that it can be seen by the plot function
        global sol
        
        sol = {
                "Pimp":  Pimp.X.copy(),
                "Pexp":  Pexp.X.copy(),
                "H":     H_1.X.copy(),
                "SoC":   SoC.X.copy(),
                "L_BW":  L_BW.X.copy(),
                "A_DC":  A_DC.X.copy(),
                "Pch":   Pch.X.copy(),
                "Pdis":  Pdis.X.copy(),
                "P_source": P_source.X.copy(),
                "P_fan":    P_fan.X.copy(),
                "P_cooling": P_cooling.X.copy(),
                "U":     U.X.copy(),
                "TRCU": U[0, :].X.copy(),
                "QRCU": U[1, :].X.copy(),
                "PS1":    U[2, :].X.copy(),
                "PS2":    U[3, :].X.copy(),
                "X_1":   X_1.X.copy(),
                "Ti":   X_1[:2, :].X.copy(),
                "To":   X_1[2:4, :].X.copy(),
            }

    for i in range(1, cf.HOURS):
        energy_cost = 1 * np.sum(p_buy[i] * sol["Pimp"] - p_sell[i] * sol["Pexp"] + p_gas[i]*(heat_demand[i] - sol["H"]*1e-3))
        heat_pen    = np.sum(1 * p_gas[i] * (heat_demand[i] - sol["H"]*1e-3)**2)

    print(f"\nOptimal objective: {m.obj_val:.4f}")
    print(f"  Energy cost term: {energy_cost:.4f}")
    print(f"  Heat penalty term: {heat_pen:.4f}")

    # store objective values based on mode
    global Single_Obj 
    global Single_Energy_Cost 
    global Single_Heat_Penalty 

    global Multi_Obj 
    global Multi_Energy_Cost
    global Multi_Heat_Penalty
    
    if mode == 0:
        Single_Obj = m.obj_val
        Single_Energy_Cost = energy_cost
        Single_Heat_Penalty = heat_pen
    elif mode == 1:
        Multi_Obj = m.obj_val
        Multi_Energy_Cost = energy_cost
        Multi_Heat_Penalty = heat_pen

    # %%
    # export 24 cf.HOURS scehdule to csv
    import csv

    if mode == 0:
        #write to single objective csv
        with open('schedule_single_objective.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Hour', 'Pimp (kW)', 'Pexp (kW)', 'SoC', 'Batch Workload Zone 1', 'Batch Workload Zone 2', 'Active Servers', 'Heat Recovered (kWth)', 'Pch (kW)', 'Pdis (kW)', 'TRCU (C)', 'QRCU (m3/s)', 'PS1 (W)', 'PS2 (W)'])
            for hour in range(cf.HOURS):
                writer.writerow([hour,
                                sol["Pimp"][hour],
                                sol["Pexp"][hour],
                                sol["SoC"][hour],
                                sol["L_BW"][0][hour],
                                sol["L_BW"][1][hour],
                                sol["A_DC"][hour],
                                sol["H"][hour],
                                sol["Pch"][hour],
                                sol["Pdis"][hour],
                                sol["TRCU"][hour],
                                sol["QRCU"][hour],
                                sol["PS1"][hour],
                                sol["PS2"][hour]])    
                
    elif mode == 1:
        #write to multi-objective csv
        with open('schedule_multi_objective.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Hour', 'Pimp (kW)', 'Pexp (kW)', 'SoC', 'Batch Workload Zone 1', 'Batch Workload Zone 2', 'Active Servers', 'Heat Recovered (kWth)', 'Pch (kW)', 'Pdis (kW)', 'TRCU (C)', 'QRCU (m3/s)', 'PS1 (W)', 'PS2 (W)'])
            for hour in range(cf.HOURS):
                writer.writerow([hour,
                                sol["Pimp"][hour],
                                sol["Pexp"][hour],
                                sol["SoC"][hour],
                                sol["L_BW"][0][hour],
                                sol["L_BW"][1][hour],
                                sol["A_DC"][hour],
                                sol["H"][hour],
                                sol["Pch"][hour],
                                sol["Pdis"][hour],
                                sol["TRCU"][hour],
                                sol["QRCU"][hour],
                                sol["PS1"][hour],
                                sol["PS2"][hour]])
    

    # %%
    # Save Stage-1 artifacts needed by Stage-2 (so Stage-2 can run without importing Stage-1)
    # These are small and stable: mode, bounds, prices, and discrete thermal model matrices.
    artifacts_path = "stage1_artifacts.npz"
    try:
        np.savez(
            artifacts_path,
            mode=np.array([mode], dtype=int),
            L_max=np.array([L_max], dtype=float),
            p_buy=np.array(p_buy, dtype=float),
            p_sell=np.array(p_sell, dtype=float),
            p_gas=np.array(p_gas, dtype=float),
            A_5min=np.array(A_5min, dtype=float),
            B_5min=np.array(B_5min, dtype=float),
        )
        print(f"Saved Stage-1 artifacts to {artifacts_path}")
    except Exception as e:
        print(f"WARNING: Failed to save Stage-1 artifacts ({artifacts_path}): {e}")


# to execute main function when run python script directly
if __name__ == "__main__":
    main()

# %%
# Convert current .ipynb to .py file so that it can be run as a script
# !jupyter nbconvert --to script MSc_2_servers_stage_1.ipynb

#%% Plots
def plot():
    # import numpy as np
    # import matplotlib.pyplot as plt

    # Supply and demand 
    supply = P_solar[0:cf.HOURS] + P_wind[0:cf.HOURS] + sol["Pdis"]  + sol["Pimp"]

    demand = ff.server_consumption(1.5, sol["A_DC"], np.sum(sol["L_BW"], axis=0), cf.L_RATE, cf.P_IDLE, cf.P_PEAK) \
            + ff.server_consumption(1.5, sol["A_DC"], mf.L_IW, cf.L_RATE, cf.P_IDLE, cf.P_PEAK)\
            + sol["P_cooling"]*1e-3 + sol["Pexp"] + sol["Pch"]

    # Time steps for plots
    t = np.arange(cf.HOURS)
    y = [
        P_solar[0:cf.HOURS],
        P_wind[0:cf.HOURS],
        sol["Pdis"],
        sol["Pimp"]
    ]

    labels = ["Solar Power", "Wind Power", "Battery Discharge", "Grid Import"]
    colors = ["gold", "skyblue", "lightcoral", "violet"]

    # plot supply contributions
    plt.figure()
    plt.figure(figsize=(8, 4))
    plt.stackplot(t, y, labels=labels, colors=colors, alpha=0.8)
    plt.title("Renewable Power Generation (Stacked Area)")
    plt.xlabel("Time step")
    plt.ylabel("Power (kW)")
    plt.legend(loc="upper left")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.show()

    # results plots
    ff.plot_timeseries_multi(t, [supply, demand], ["Supply", "Demand"], "Supply and Demand Balance", ylabel="kW")
    ff.plot_timeseries_multi(t, [sol["Pimp"], sol["Pexp"]], ["Import", "Export"], "Import/Export Split", ylabel="kW")
    ff.plot_timeseries_multi(t, [heat_demand[:cf.HOURS], sol["H"]*1e-3], ["Heat Demand", "Recovered Heat"], "Heat Demand vs Recovered Heat", ylabel="kW(th)")
    ff.plot_timeseries_multi(t, [p_buy[:cf.HOURS], p_sell[:cf.HOURS]], ["Buy price", "Sell price"], "Electricity Prices", ylabel="£/kWh")
    ff.plot_timeseries_multi(t, [sol["Pch"], sol["Pdis"]], ["Charge", "Discharge"], "Battery Charge/Discharge Power", ylabel="kW")
    ff.plot_timeseries_multi(t, [sol["SoC"]], ["State of Charge"], "SoC Over Time", ylabel="SoC")
    ff.plot_timeseries_multi(t, [np.sum(sol["L_BW"], axis=0), mf.L_IW[:cf.HOURS]], ["Batch Workload", "Interactive Workload"], "Data Centre Load Profile", ylabel="Load (requests/hour)")
    ff.plot_timeseries_multi(t, [sol["A_DC"]], ["Active Servers"], "Fraction of Active Servers Over Time", ylabel="Fraction")


    # %%
    # total computing load
    from python_code.functions_file import QoS_function

    total_load = np.sum(sol["L_BW"], axis=0) + mf.L_IW[:cf.HOURS]
    ff.plot_timeseries_multi(t, [sol["L_BW"][0].T, sol["L_BW"][1].T], ["Batch Workload Zone 1", "Batch Workload Zone 2"], "Batch Workload Dynamic", ylabel="Requests per hour")
    ff.plot_timeseries_multi(t, [total_load], ["Total Load"], "Total Data Centre Load", ylabel="Requests per hour")

    # plot server temperaure over the period
    ff.plot_timeseries_multi(t, [sol["PS1"].T, sol["PS2"].T], ["Server Power Zone 1", "Server Power Zone 2"], "Server Power Consumption Dynamic", ylabel="Watt")  
    ff.plot_timeseries_multi(t, [sol["L_BW"][0].T, sol["L_BW"][1].T], ["Batch Workload Zone 1", "Batch Workload Zone 2"], "Batch Workload Dynamic", ylabel="Requests per hour")
    ff.plot_timeseries_multi(t, [sol["Ti"][1:24].T,sol["Ti"][25:48].T], ["Inlet T1", "Inlet T2"], "Inlet Temperature Dynamic", ylabel="Degree Celcius")
    ff.plot_timeseries_multi(t, [sol["To"][1:24].T,sol["To"][25:48].T], ["Outlet T1", "Outlet T2"], "Outlet Temperature Dynamic", ylabel="Degree Celcius")
    ff.plot_timeseries_multi(t, [sol["TRCU"].T], ["TRCU", "QRCU"], "Cooling Setting", ylabel="Degree Celcius")
    ff.plot_timeseries_multi(t, [sol["QRCU"].T], ["QRCU"], "Cooling Setting", ylabel="m^3 per s")
    ff.plot_timeseries_multi(t[1:23], [sol["P_cooling"][1:23].T], ["P_cooling"], "Cooling Power Consumption", ylabel="W")

    #QoS delay plot 
    QoS = - cf.MAX_DELAY * (mf.L_IW[:cf.HOURS] / sol["A_DC"] - cf.L_RATE)
    ff.plot_timeseries_multi(t, [QoS], ["QoS Delay"], "Quality of Service Delay", ylabel="cf.HOURS")

    #check ratio of interactive load and active servers
    ratio_IW_A_DC = mf.L_IW[:cf.HOURS] / sol["A_DC"]
    ff.plot_timeseries_multi(t, [ratio_IW_A_DC], ["IW / Active Servers"], "Ratio of Interactive Workload to Active Servers", ylabel="Requests per server per hour")

    # %%
    # Plot stacked bar chart of computing load components

    # Extract data
    BW1 = sol["L_BW"][0].T          # (cf.HOURS,)
    BW2 = sol["L_BW"][1].T
    IW  = mf.L_IW[:cf.HOURS]
    BW_total = BW1 + BW2
    total_load = IW + BW_total

    t_hours = np.arange(cf.HOURS)

    plt.figure(figsize=(8, 4))

    # bars
    plt.bar(t_hours, IW, label="Interactive Load (IW)", alpha=0.8)
    plt.bar(t_hours, BW1, bottom=IW, label="Batch Zone 1 (BW1)", alpha=0.8)
    plt.bar(t_hours, BW2, bottom=IW + BW1, label="Batch Zone 2 (BW2)", alpha=0.8)

    #lines
    plt.plot(t_hours, IW, color="black", linewidth=2, linestyle="--",
            label="IW (original line)")
    plt.plot(t_hours, L_BW_0, color="red", linewidth=2, linestyle="-.",
            label="BW original line")
    plt.plot(t_hours, total_load, color="blue", linewidth=2,
            label="Total Load (IW + BW)")

    plt.title("Data Centre Load: Stack and Original Curves for ")
    plt.xlabel("Hour")
    plt.ylabel("Requests per Hour")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.show()

    # plot accumalation of batchworkload to check that it complies with end of day constrain
    acc_LBW = np.zeros(cf.HOURS)
    acc_sol_LBW = np.zeros(cf.HOURS)

    for i in range(1,cf.HOURS):
        acc_LBW[i] = L_BW_0[i] + acc_LBW[i-1]
        acc_sol_LBW[i] = sol["L_BW"][0][i] + sol["L_BW"][1][i] + acc_sol_LBW[i-1]

    ff.plot_timeseries_multi(t, [acc_LBW, acc_sol_LBW], ["L_BW", "schl_LBW"], "Accumulated BW", ylabel="BW")


# %%
 


