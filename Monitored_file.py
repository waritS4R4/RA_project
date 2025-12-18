# This is a file for data acquisition for time changing variables
import numpy as np
import pandas as pd

from constant_file import NUMBER_OF_SERVERS
import constant_file as cf

# Measured time stamp
T = 1*60                 # Number of measurement points over the entire period (1 minute sampling for 1 hours)
TIME = np.arange(0, T)   # Time vector

# Interval that the model is construct
# because Qoh and Qoc and Ql depend on Qs and Qs depends on Temperature therefore the model is reestimate every measuring interval
CURRENT_DAY = 1         # Current day in a year for G and T_amb
CURRENT_HOUR = 0        # Current hour in a day for G and T_amb, this will be update in 2nd stage
CURRENT_INTERVAL = 10  # Example current interval index

# this is an example of a monitored data
# INLET_TEMPERATURE = np.random.uniform(15, 20, size=T)
# SERVER_TEMPERATURE = np.random.uniform(20, 30, size=T)
# OUTLET_TEMPERATURE = np.random.uniform(30, 40, size=T)
# RCU_TEMPERATURE = np.random.normal(loc=22, scale=1, size=T)  # mean=22, std=1, 60 values

# Import the datasets 
# Load the CSV file into a DataFrame
df = pd.read_csv("Example_datasets.csv")
data_length = df.shape[0]

# print("Data length (number of rows):", data_length)
# Temperature data for 10 servers
inlet_cols = [f"TI_{i}_C" for i in range(1, 11)]
server_cols = [f"TS_{i}_C" for i in range(1, 11)]
outlet_cols = [f"TO_{i}_C" for i in range(1, 11)]
INLET_TEMPERATURE = df[inlet_cols].values 
SERVER_TEMPERATURE = df[server_cols].values
OUTLET_TEMPERATURE = df[outlet_cols].values

# Cooling units data
RCU_TEMPERATURE = df["TRCU"].values
# RCU_AIRFLOW = df["QRCU"].values
TIME_STAMP = df["time"].values

# Server power consumption data for 10 servers
SERVER_POWER = df[[f"PS_{i}_kW" for i in range(1, 11)]].values
SERVER_POWER = SERVER_POWER*1000  # Convert kW to W

# dimension of datas [rowxcolumn] = [Time(180), NUMBER_OF_SERVERS(10)]
# print("INLET_TEMPERATURE shape:", INLET_TEMPERATURE.shape)
# print("SERVER_TEMPERATURE shape:", SERVER_TEMPERATURE.shape)
# print("OUTLET_TEMPERATURE shape:", OUTLET_TEMPERATURE.shape)
# print("RCU_TEMPERATURE shape:", RCU_TEMPERATURE.shape)
## print("RCU_AIRFLOW shape:", RCU_AIRFLOW.shape)
# print("SERVER_POWER shape:", SERVER_POWER.shape)

# check if successful
# print("Data loaded successfully")
# print("INLET_TEMPERATURE shape:", INLET_TEMPERATURE.shape)
# print("SERVER_TEMPERATURE shape:", SERVER_TEMPERATURE.shape)
# print("OUTLET_TEMPERATURE shape:", OUTLET_TEMPERATURE.shape)
# print("RCU_TEMPERATURE shape:", RCU_TEMPERATURE.shape)
# print("RCU_AIRFLOW shape:", RCU_AIRFLOW.shape)
# print("SERVER_POWER shape:", SERVER_POWER.shape)

# Server power consumption data

# Measured States Variables
Xmeas = np.zeros((30, INLET_TEMPERATURE.shape[0]))  # State vector [TI; TS; TO] for NUMBER_OF_SERVERS servers
for j in range(INLET_TEMPERATURE.shape[0]):  # Example time index for measurement extraction at time 0th min
    for i in range(NUMBER_OF_SERVERS):
        Xmeas[i, j] = INLET_TEMPERATURE.T[i, j]    # TI
        Xmeas[i + 10, j] = SERVER_TEMPERATURE.T[i, j]  # TS
        Xmeas[i + 20, j] = OUTLET_TEMPERATURE.T[i, j]  # TO

# Check data shapes 
# print("INLET_TEMPERATURE shape:", INLET_TEMPERATURE.shape)  # Should be (T, NUMBER_OF_SERVERS)
# print("Xmeas shape:", Xmeas.shape)  # Should be (30,) for 10 servers at any time point
# print("INLET_TEMPERATURE.shape[0]",INLET_TEMPERATURE.shape[0])

# Example of Interactive load (# number of request)
L_DC = np.array([600,550,520,500,520,600,800,1000,1200,1300,1400,1500,
                 1500,1450,1400,1350,1300,1250,1200,1100,1000,900,800,700])
# L_DC = L_DC * NUMBER_OF_SERVERS  # Total data center load for all servers

L_IW = np.array([300,280,260,250,260,350,600,800,1000,1100,1150,1200,
                 1200,1150,1100,1000,900,800,700,600,500,400,350,320])
# L_IW = L_IW * NUMBER_OF_SERVERS  # Total interactive workload for all servers

# Example of interactive load with 5 minutes interval forecasting
L_DC_5min = np.repeat(L_DC, cf.STEP) 
L_IW_5min = np.repeat(L_IW, cf.STEP) 

# Basic check
Total_L_BW = np.sum(L_DC - L_IW)
Avg_hourly_L_BW = Total_L_BW/cf.HOURS
L_max = np.max(L_IW) + Avg_hourly_L_BW