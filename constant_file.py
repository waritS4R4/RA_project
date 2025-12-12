# this file containts all the constants used in the MSc Thesis Modelling .ipynb and PEM.py files
import numpy as np

# Define constants for data centre modelling
THERMAL_INERTIA = 500
ROOM_SURFACE_AREA = 200
HEAT_CAPACITY_AIR = 1005
AIR_DENSITY = 1.2
NUMBER_OF_SERVERS = 2 # Total number of servers in the data centre (regardless of active or not)
NUMBER_OF_RACKS = 1 # Total number of racks in the data centre
SERVER_CAPACITY = 500 # Maximum server power
SAMPLING_TIME = 1  # 1 minutes in seconds
HOURS = 24            # hours in a day for upper layers
INLET_VOLUME  = 1             # in m^3
OUTLET_VOLUME = 1             # in m^3

# Power consumption parameters
P_IDLE = 100 # W
P_PEAK = SERVER_CAPACITY # W
P_STATIC = 50 # W
c_pue = 1.5  # Power usage effectiveness
L_RATE = 300  # Fixed server rate (# jobs per server per slot)
MAX_DELAY = 1/60  # Maximum allowable delay in hours for batch workload this is 1 minute

# Server and cooling characteristics
# N = NUMBER_OF_SERVERS            # Number of servers and so HPCU as its rack-based
V_I = 0.6171       # [m^3]
X = THERMAL_INERTIA       # [J/°C]
RHO_A = AIR_DENSITY    # [kg/m^3]
CP_A = HEAT_CAPACITY_AIR     # [J/kg°C]
K = RHO_A * CP_A

# intial cooling conditions
TRCU_0 = 25          # Initial THPCU airflow temperature
QRCU_0 = 0.1 / 2     # Initial airflow (QHPCU) 
COP_C = 3.5      # Cooling system coefficient of performance

# Initial server temperature conditions
TI_10 = 20;  TI_20 = TI_10      # intial inlet temperature
TO_10 = 38 ; TO_20 = TO_10      # intial outlet temperature
TS_10 = 30 ; TS_20 = TS_10      # intial server temperature

PS_0 = 500       # Initial server power
SoC_0 = 0.8      # Initial state of charge
PEXE_0 = 0       # Initial executed computing load
PBAT_0 = 0       # Initial battery power

# Server initial conditions
U1_0 = 0.5       # Initial CPU utilisation
U2_0 = 0.5       # Initial CPU utilisation

# Battery parameters
ETA_CH = 0.95               # Battery charing efficiency
ETA_DCH = 0.90              # Battery discharging efficiency
dt = SAMPLING_TIME          # time step in seconds for discretisation and control
E_ESS = 5e6                 # Battery capacity for UPS for 5 minutes
ETA_LOSS = 0.01             # Self-leaking battery coefficient

# Fan cooling power coefficients
BETA_0 = 480
BETA_1 = -3073
BETA_2 = 6031

# Solar cells parameters
ETA_INVT = 0.95  # Example inverter efficiency
P_STC = 5000  # Example rated PV power at STC in W
G_STC = 1000  # Standard Test Condition irradiance in W/m^2
GAMMA = -0.004  # Example temperature coefficient in 1/°C
T_STC = 25  # Standard Test Condition cell temperature in °C
T_NOCT = 45  # Nominal Operating Cell Temperature in °C
G_NOCT = 800  # Irradiance at NOCT in W/m^2 

# Wind turbine parameters
# Example parameters for a small wind turbine Hummer H25.0-100KW (https://en.wind-turbine-models.com/turbines/1682-hummer-h25.0-100kw)
V_CUT_IN = 2.5         # Cut-in wind speed in m/s
V_CUT_OUT = 20       # Cut-out wind speed in m/s
V_RATED = 10         # Rated wind speed in m/s
P_RATED = 100000      # Rated power in W

# Initial guess coefficients for PEM model 
Fi = 0.0   # Recirculation coefficients
Di = np.zeros(10)  # Leakage coefficients
Ei = 0.07

i = 0
for i in range(1,NUMBER_OF_SERVERS):
    Di[i] = i/NUMBER_OF_SERVERS  # Leakage coefficients


# System constraints
# Bounds for decision variables
# QRCU_min, QRCU_max  = 0.01, 0.05 #airflow rate limits
QRCU_min, QRCU_max  = 0 , 0.1 #airflow rate limits
TRCU_min, TRCU_max  = 0, 60     #cold air supply temperature limits
Ps_min,    Ps_max     = 0, 2500    # server power limits (assume 5 servers with 500 W each for each zone)
Pexe_min,  Pexe_max   = 0, 2.000    # executed computing load limits differences
Ti_min,    Ti_max     = 0, 30      # inlet air temperature limits
# Ts_min,    Ts_max     = 0, 30      # inlet air temperature limits
To_min,    To_max     = 10, 40     # outlet air temperature limits
SoC_min,   SoC_max    = 0.5, 0.9   # battery state of charge limits
Pg_max                =  5.000           # grid import/export limits
Pimp_min,  Pimp_max   = 0, Pg_max  # grid import/export limits
Pexp_min,  Pexp_max   = 0, Pg_max      # grid export limits
Pbat_max              = 2.000       # battery charge/discharge power limit (kW)
Pch_min,   Pch_max    = 0, Pbat_max # battery charge power limits
Pdis_min,  Pdis_max   = 0, Pbat_max # battery discharge
# L_max = np.max(L_DC)                # data centre number of load limit

# MPC parameters
interval = 5  # control interval in minutes
horizon = 4  # prediction horizon in hours
STEP = int(horizon * 60 / interval)  # number of steps in the horizon
step = int( 60 / interval)
