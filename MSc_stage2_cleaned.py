# %%
#read optimal hourly schedule from first stage
import numpy as np
import pandas as pd
import gurobipy as gp
from gurobipy import Model, GRB, quicksum
import matplotlib.pyplot as plt

# import all the neccessary dependencies
import functions as ff
import constant_file as cf
import Monitored_file as mf # L_DC, L_IW, CURRENT_HOUR
from Monitored_file import L_DC, L_IW
import MSc_stage1_cleaned as stg1


def initialise(h):
    # declare golbal variables
    global P_wind_5min, P_wind_5min_forecast
    global P_solar, P_solar_5min, P_solar_5min_forecast
    global heat_demand_5min, heat_demand_5min_forecast
    global L_BW_0_5min_forecast, L_DC_5min_forecast, L_IW_5min_forecast, L_DC_5min, L_IW_5min
    global p_buy_5min, p_gas_5min, p_sell_5min
    global optimal_schedule

    # Load the optimal schedule based on the selected mode extracted from the 
    if stg1.mode == 0:
        optimal_schedule = pd.read_csv('schedule_single_objective.csv')
    elif stg1.mode == 1:
        optimal_schedule = pd.read_csv('schedule_multi_objective.csv')
    else:
        raise ValueError("Invalid mode selected.")
    
    # import the hourly solar, wind and heat from stage 1
    df_gen = pd.read_csv('generation_and_heat_demand_data.csv')
    P_solar = df_gen['Solar_Power_kW'].values
    P_wind = df_gen['Wind_Power_kW'].values
    heat_demand = df_gen['Heat_Demand_kW'].values

    # inditify which hours to extract from optimal schedule
    i = h # this is the first our of the short period

    # 5 minutes solar generation forecast 
    P_solar_5min = np.repeat(P_solar[i:i+cf.horizon], 12)  # 12 intervals of 5 minutes in an hour
    # import 5 minute forecaste from solcast
    ghi_5min_forecast = pd.read_csv('ghi_5mins_1jan2022.csv')['ghi'].values
    temp_5min_forecast = pd.read_csv('ghi_5mins_1jan2022.csv')['air_temp'].values
    
    # calculate solar output 5 minutes
    T_cell = np.zeros(len(ghi_5min_forecast))
    P_solar_5min_forecast = np.zeros(len(ghi_5min_forecast))
    for k in range(len(ghi_5min_forecast)):
        T_cell[k] = ff.cell_temperature(temp_5min_forecast[k], ghi_5min_forecast[k], cf.T_NOCT, cf.G_NOCT)  # Cell temperature
        P_solar_5min_forecast[k] = ff.pv_output(cf.ETA_INVT, cf.P_STC, ghi_5min_forecast[k], cf.G_STC, cf.GAMMA, T_cell[k], cf.T_STC)

    # 5 minutes wind generation forecast
    P_wind_5min = np.repeat(P_wind[i:i+cf.horizon], 12)  # 12 intervals of 5 minutes in an hour
    P_wind_5min_forecast = P_wind_5min + P_wind_5min*pd.read_csv('noise_patterns_5min.csv')['wind_noise'][:len(P_wind_5min)]   # adding 10% noise

    # 5 minutes heat demand forecast
    heat_demand_5min = np.repeat(heat_demand[i:i+cf.horizon], 12)  # 12 intervals of 5 minutes in an hour
    heat_demand_5min_forecast = heat_demand_5min + heat_demand_5min*pd.read_csv('noise_patterns_5min.csv')['heat_noise'][:len(heat_demand_5min)]   # adding 5% noise

    # computing load noise
    # Breakdown of hourly workload into 5-minute intervals
    L_DC_5min = np.repeat(L_DC[i:i+cf.horizon]/(60/cf.interval), int(60/cf.interval))
    # L_DC_5min = np.repeat(L_DC/(60/cf.interval), int(60/cf.interval))  # Repeat each hourly value 12 times to create 5-minute intervals
    L_DC_5min_forecast = L_DC_5min + L_DC_5min*pd.read_csv('noise_patterns_5min.csv')['interactive_workload_noise'][:len(L_DC_5min)]   # adding 10% noise

    L_IW_5min = np.repeat(L_IW[i:i+cf.horizon]/(60/cf.interval), int(60/cf.interval))
    # L_IW_5min = np.repeat(L_IW/(60/cf.interval), int(60/cf.interval))  # Repeat each hourly value 12 times to create 5-minute intervals
    L_IW_5min_forecast = L_IW_5min + L_IW_5min*pd.read_csv('noise_patterns_5min.csv')['interactive_workload_noise'][:len(L_IW_5min)]   # adding 10% noise

    # Arriving batch load at each interval
    L_BW_0_5min_forecast = (L_DC_5min_forecast - L_IW_5min_forecast) # exact batch workload at each time step

    # electricity and gas prices
    p_buy_5min = np.repeat(stg1.p_buy, 12)
    p_sell_5min = np.repeat(stg1.p_sell, 12)
    p_gas_5min = np.repeat(stg1.p_gas, 12)

    #save the first hourly forecast to csv so that i can be used later in the results plots
    

    
    # %% [markdown]
    # # Extract optimal schedule from the results first stage

    # %%
    # Extract control actions from optimal schedule for use in second stage MPC
    """ 
    1. Pimp (kW)
    2. Pexp (kW)
    3. Pbat_ch (kW)
    4. Pbat_dis (kW)
    5. QRCU (kW)
    6. TRCU (°C)"""

    # make the variables be global so that it can be seen by main 
    global P_imp_opt, P_exp_opt, P_bat_ch_opt, P_bat_dis_opt, Q_RCU_opt, T_RCU_opt
    global PS1_opt, PS2_opt, SoC_opt, LBW1_opt, LBW2_opt 

    # extend control action to 5 minutes interval for the first 4 hours (48 intervals)
    P_imp_opt = np.repeat(optimal_schedule['Pimp (kW)'].values[i:i+4], 12)
    P_exp_opt = np.repeat(optimal_schedule['Pexp (kW)'].values[i:i+4], 12)
    P_bat_ch_opt = np.repeat(optimal_schedule['Pch (kW)'].values[i:i+4], 12)
    P_bat_dis_opt = np.repeat(optimal_schedule['Pdis (kW)'].values[i:i+4], 12)
    Q_RCU_opt = np.repeat(optimal_schedule['QRCU (m3/s)'].values[i:i+4], 12)
    T_RCU_opt = np.repeat(optimal_schedule['TRCU (C)'].values[i:i+4], 12)
    PS1_opt = np.repeat(optimal_schedule['PS1 (W)'].values[i:i+4], 12)
    PS2_opt = np.repeat(optimal_schedule['PS2 (W)'].values[i:i+4], 12)
    SoC_opt = np.repeat(optimal_schedule['SoC'].values[i:i+4], 12)
    LBW1_opt = np.repeat(optimal_schedule['Batch Workload Zone 1'].values[i:i+4], 12)
    LBW2_opt = np.repeat(optimal_schedule['Batch Workload Zone 2'].values[i:i+4], 12)

    # %%
    # Upper layer optimisation for day-ahead scheduling of data centre with solar and battery storage
    #------------------------ Gurobi Optimisation--------------------------
    options = {                 # Retrieve Gurobi licence
        "WLSACCESSID": "ee9bea66-ab05-406d-91a7-20582d51dfd6",
        "WLSSECRET": "5d1f81b2-4889-49d3-a1a2-796de424605a",
        "LICENSEID": 2712303,
    }
        
    # Data (arrays of length T)
    T = len(P_solar)          # p_buy[t], p_sell[t]
    #delta_t = 60*60            # 1 hr interval for power cost because ( price is in $/kWh )

    # Constraints:
    """constraints:
    1. Power balance constraint
    2. Battery operational constraints
    3. Solar power generation constraints
    4. Temperature constraints
    5. Cooling power constraints
    6. Computing load constraints"""

    # check that the  bounds are feasible
    assert (cf.Ps_max)*cf.STEP >= np.sum(ff.server_consumption(cf.c_pue, 1, mf.L_DC, cf.L_RATE, cf.P_IDLE, cf.P_PEAK)), "Server power max limit too low for the IW+BW workload"

def initialise_plot():
# plot the forecasts for verification
    time_5min = np.arange(cf.STEP)  # time in hours
    ff.plot_timeseries_multi(time_5min, 
                        [P_solar_5min_forecast,  P_solar_5min], 
                        labels=['5-minute', 'Hourly'],
                        title='5-Minute Generation Forecast vs Time',
                        ylabel='Generation (kW)',
                        xlabel='Time (hours)')   
        
    ff.plot_timeseries_multi(time_5min, 
                        [P_wind_5min_forecast, P_wind_5min], 
                        labels=['5-minute', 'Hourly'],
                        title='5-Minute Generation Forecast vs Time',
                        ylabel='Generation (kW)',
                        xlabel='Time (hours)')        

    ff.plot_timeseries_multi(time_5min, 
                        [heat_demand_5min_forecast, heat_demand_5min], 
                        labels=['5-minute', 'Hourly'],
                        title='5-Minute Heat Demand Forecast vs Time',
                        ylabel='Heat Demand (kW)',
                        xlabel='Time (hours)')    

    ff.plot_timeseries_multi(time_5min, 
                        [L_DC_5min_forecast, L_DC_5min], 
                        labels=['5-minute', 'Hourly'],
                        title='5-Minute Interactive Workload Forecast vs Time',
                        ylabel='Interactive Workload (kW)',
                        xlabel='Time (hours)')    

    ff.plot_timeseries_multi(time_5min, 
                        [L_IW_5min_forecast, L_IW_5min], 
                        labels=['5-minute', 'Hourly'],
                        title='5-Minute Batch Workload Forecast vs Time',
                        ylabel='Batch Workload (kW)',
                        xlabel='Time (hours)')  

# %%
def main():
    options = {                 # Retrieve Gurobi licence
    "WLSACCESSID": "ee9bea66-ab05-406d-91a7-20582d51dfd6",
    "WLSSECRET": "5d1f81b2-4889-49d3-a1a2-796de424605a",
    "LICENSEID": 2712303,
    }   
    # gurobi model for second stage MPC
    # read final values from the stored csv file
    # import the previous period final states as initial conditions

    # -array for storing final states extracted from csv files
    Ti = np.zeros(cf.NUMBER_OF_SERVERS)
    To = np.zeros(cf.NUMBER_OF_SERVERS)

    # check is the current hour is the initial hour
    if mf.CURRENT_HOUR == 0:
        TI_0 = np.full(2, cf.TI_10)   # initial inlet temp for all servers
        TO_0 = np.full(2, cf.TO_10)   # initial outlet temp for all servers
        X0 = np.concatenate([TI_0, TO_0])          # shape (20,) for 10 servers

        TRCU_0_arr = np.full(1, cf.TRCU_0)  # initial cold air supply temperature for single RCU per rack
        QRCU_0_arr = np.full(1, cf.QRCU_0)  # initial airflow for single RCU
        PS_0_arr = np.full(cf.NUMBER_OF_SERVERS, cf.PS_0)  # initial server power for all servers
        U0 = np.concatenate([TRCU_0_arr, QRCU_0_arr, PS_0_arr])

        # reassign SoC value
        SoC_0 = cf.SoC_0

    # if not the first hour
    elif mf.CURRENT_HOUR > 0:
        final_states = pd.read_csv('states.csv')
        X0 = np.zeros(2*cf.NUMBER_OF_SERVERS) #number of zones is 2
        for i in range (cf.NUMBER_OF_SERVERS):
            X0[i] = Ti[i]
            X0[i+cf.NUMBER_OF_SERVERS] = To[i]

        TRCU_0_arr = final_states["TRCU_final"][mf.CURRENT_HOUR-1]
        QRCU_0_arr = final_states["QRCU_final"][mf.CURRENT_HOUR-1]
        
        PS1_0_arr = PS1_opt[mf.CURRENT_HOUR-1] # use the previous hour optimal server power as initial condition (at the beginning of the hour)
        PS2_0_arr = PS2_opt[mf.CURRENT_HOUR-1] # unit is watt
        
        # reassign SoC value
        SoC_0 = final_states["SoC_final"][mf.CURRENT_HOUR-1]

        U0 = np.array([TRCU_0_arr, QRCU_0_arr, PS1_0_arr, PS2_0_arr])

    # %%
    # Decision vars
    # state variables

    if stg1.mode == 0:
        print("this is 2nd stage for Uni-optimisation")
    elif stg1.mode == 1:
        print("this is 2nd stage for Co-optimisation")
    else: 
        print("Error , mode is neither 1 or 0")

    with gp.Env(params=options) as env:

        m = gp.Model("Lower_Layer_Optimisation", env=env)

        # state variables
        lb_X = np.array([cf.Ti_min]*cf.NUMBER_OF_SERVERS  + [cf.To_min]*cf.NUMBER_OF_SERVERS)
        ub_X = np.array([cf.Ti_max]*cf.NUMBER_OF_SERVERS  + [cf.To_max]*cf.NUMBER_OF_SERVERS)
        #X  = m.addMVar((3*NUMBER_OF_SERVERS, cf.STEP), lb=lb_X[:, None], ub=ub_X[:, None], name="X")

        # Assume one rack with identical servers of two zones
        # X_1  = m.addMVar((2*2, cf.STEP), lb=lb_X[:, None], ub=ub_X[:, None], name="rack 1") # this is the unbounded variables to test the code flows
        X_1  = m.addMVar((2*2, cf.STEP), name="rack 1")

        # Group server power into an input list
        lb_U = np.array([cf.TRCU_min, cf.QRCU_min, cf.Ps_min, cf.Ps_min])  # For 2 servers
        ub_U = np.array([cf.TRCU_max, cf.QRCU_max, cf.Ps_max, cf.Ps_max])  # For 2 servers
        # U = m.addMVar((4, cf.HOURS), lb=lb_U[:, None], ub=ub_U[:, None], name="U")  # Control variables
        U = m.addMVar((4, cf.STEP), lb=np.tile(lb_U[:, None], (1, cf.STEP)), ub=np.tile(ub_U[:, None], (1, cf.STEP)), name="U")  # Control variables

        L_BW = m.addMVar((cf.NUMBER_OF_SERVERS, cf.STEP), lb=0, ub=stg1.L_max, name="L_BW")  # Data centre load
        A_DC = m.addMVar((cf.STEP), lb=0, ub=5,     name="A_DC")  # Data centre load
        L    = m.addVars(cf.STEP, name="L")          # total load
        P_dc = m.addVars(cf.STEP, name="P_dc")       # data centre power
        
        SoC  = m.addMVar(cf.STEP, lb=cf.SoC_min, ub=cf.SoC_max, name="SoC")   # Battery SoC
        H_sub = m.addMVar(cf.STEP, name="H_sub")  # Auxiliary, no explicit bounds
        H_1   = m.addMVar(cf.STEP, lb=0, name="H_1")                          # Heat extracted 

        Pimp = m.addMVar(cf.STEP,  lb=0, ub = cf.Pg_max, name="Pimp")  # Grid import (≥0)
        Pexp = m.addMVar(cf.STEP, lb=0, ub = cf.Pg_max, name="Pexp")  # Grid export (≥0)
        Pch  = m.addMVar(cf.STEP, lb=0,     ub=cf.Pbat_max, name="Pch") # Battery charge (≥0)
        Pdis = m.addMVar(cf.STEP, lb=0,     ub=cf.Pbat_max, name="Pdis")# Battery discharge (≥0)
        epsilon_ch = m.addMVar(cf.STEP, vtype=GRB.BINARY, name="epsilon_ch") # Charge indicator
        epsilon_dis = m.addMVar(cf.STEP, vtype=GRB.BINARY, name="epsilon_dis") # Discharge indicator
        P_source = m.addMVar(cf.STEP,  name="P_source")  # Cooling source power
        P_fan    = m.addMVar(cf.STEP,  name="P_fan")       # Cooling fan power
        P_cooling = m.addMVar(cf.STEP,  name="P_cooling") # Total cooling power
        avg_TRCU = m.addMVar(cf.STEP,  name="Avg_TRCU") # Average cooling liuid incoming temperature
        avg_TO = m.addMVar(cf.STEP,  name="Avg_T0") # Average outlet zone temperature

        # initial conditions of previously determined variables at t = 0
        m.addConstr(X_1[:, 0] == X0, name="initial_states_X_1") # Initial condition for temperatures states
        m.addConstr(SoC[0] == SoC_0, name="initial_states_SoC")  # Initial condition for battery SoC
        m.addConstr(U[:, 0] == U0, name="initial_inputs_U_0")          # Initial condition for control inputs
        m.addConstr(L_BW[:,0] == np.zeros(cf.NUMBER_OF_SERVERS), name="initial_LBW") # initial batch workload from previous operational period

        # total load and data centre power consumption constraints
        for t in range(cf.STEP):
            m.addConstr(
            L[t] == quicksum(L_BW[j, t] for j in range(cf.NUMBER_OF_SERVERS)) + L_IW_5min_forecast[t],name=f"total_load_{t}"
            )
            
            # P_dc_expr = server_consumption(c_pue, 1, L[t], L_RATE, P_IDLE, P_PEAK)  # must return a LinExpr
            m.addConstr(P_dc[t] == (A_DC[t] * (cf.P_IDLE + (cf.c_pue-1)) + L[t]*(cf.P_PEAK-cf.P_IDLE)/(cf.L_RATE))/1e3, name=f"pdc_def_{t}")
    
        # # Load splits constraints
        # for t in range(0,cf.STEP):
        #     total_L_BW = quicksum(L_BW[j,t-1] for j in range(NUMBER_OF_SERVERS)) # total BW that is schedule before time t
        #     m.addConstr(quicksum(L_BW[j, t] for j in range(NUMBER_OF_SERVERS)) <= quicksum(L_BW_0_5min_forecast[t] for t in range(0,t)) - total_L_BW, name=f"eq_3d_L_{t}") # batch worklaod that is schedule must be smaller than sum of incoming btach workload - already schedule worklaod

        cum_arrival = 0
        cum_scheduled = 0

        for t in range(cf.STEP):
            # update cumulative arrivals (data, not decision vars)
            cum_arrival += L_BW_0_5min_forecast[t]

            # update cumulative scheduled (decision vars)
            cum_scheduled += quicksum(L_BW[j, t] for j in range(cf.NUMBER_OF_SERVERS))

            # cannot have scheduled more than has arrived up to time t
            m.addConstr(
                cum_scheduled <= cum_arrival,
                name=f"cumulative_batch_feasibility_{t}"
        )


        #End of day workload, all of the schedule workload must be executed within a day
        m.addConstr(quicksum(L_BW[j,t] for j in range(cf.NUMBER_OF_SERVERS) for t in range(1,cf.STEP)) == quicksum(L_BW_0_5min_forecast[t] for t in range(cf.STEP)),
                    name="end_of_day_workload")

        # Constraints for QoS: limited time delay for interactive workload
        for t in range(1,cf.STEP):
            m.addConstr(A_DC[t]*cf.L_RATE - L_IW_5min_forecast[t]>= 0, name=f"A_DC_{t}")
            m.addConstr(A_DC[t]*(cf.L_RATE - 1/cf.MAX_DELAY) - L_IW_5min_forecast[t] <= 0, name=f"qos_delay_{t}")

        # Update temperature dynamics using discretized state-space model
        for t in range(1,cf.STEP):  # start from 1 to avoid negative index
            # Server power consumption constraints based on current load and cooling conditions
            m.addConstr(
                U[2, t] == ff.server_consumption(1.5, A_DC[t], L_BW[0, t]+L_IW_5min_forecast[t]/2, cf.L_RATE, cf.P_IDLE, cf.P_PEAK)*1e3, name=f"PS1_{t}" # convert to W
            )

            m.addConstr(
                U[3, t] == ff.server_consumption(1.5, A_DC[t], L_BW[1, t]+L_IW_5min_forecast[t]/2, cf.L_RATE, cf.P_IDLE, cf.P_PEAK)*1e3, name=f"PS2_{t}" # convert to W
            )

            m.addConstr(
                # Compute server power from A and L using the matrix derived from the rack based model
                X_1[:, t] == stg1.A_5min @ X_1[:, t-1] + stg1.B_5min @ U[:, t-1], name=f"temp_dynamics_X_1_{t}"
            )

            m.addConstr(
                avg_TRCU == U[1, t], name=f"avg_TRCU_{t}"
            )

            # average tmeperature outlet of the two zones
            avg_TO = (X_1[2, t] + X_1[3, t]) / 2

            # Original H
            m.addConstr(H_1[t] == cf.RHO_A * cf.CP_A * U[1,t] * (avg_TO - U[0,t]), name=f"waste_heat_recovery_{t}")  # Waste heat recovery

            # Cooling power based on COP
            #m.addConstr(P_source[t] == H_1[t] / COP_C, name=f"cooling_power_{t}")
            m.addConstr(P_source[t] == H_1[t] / cf.COP_C, name=f"cooling_power_{t}")  #try isolte the effect on cooling power from heat rev
            m.addConstr(P_fan[t] == cf.BETA_0 + cf.BETA_1*U[1, t] + cf.BETA_2*U[1, t]**2, name=f"fan_power_{t}")
            m.addConstr(P_cooling[t] == P_source[t] + P_fan[t], name=f"total_cooling_power_{t}")
        
        # constraints for final value of SoC to be equal to initial value
        m.addConstr(SoC[cf.STEP-1] == SoC_0, name="final_SoC_equals_initial")

        dev_Pimp = np.zeros(cf.STEP)
        dev_Pexp = np.zeros(cf.STEP)
        dev_SoC = np.zeros(cf.STEP)
        dev_LBW1 = np.zeros(cf.STEP)
        dev_LBW2 = np.zeros(cf.STEP)
        
        M = cf.Pbat_max

        # Power and heat balance constraints
        for t in range(1,cf.STEP):

            # Power balance constraint
            Pdc_expr = ff.server_consumption(1.5, A_DC[t], L[t], 2000, cf.P_IDLE, cf.P_PEAK)
            m.addConstr(
                Pimp[t] - Pexp[t] +  Pdis[t] - Pch[t] + P_solar_5min_forecast[t] - P_cooling[t]*1e-3 - Pdc_expr == 0,
                name=f"power_balance_{t}"
            )
            
            m.addConstr(Pdis[t] <= M * epsilon_dis[t], name=f"discharge_power_limit_{t}")
            m.addConstr(Pch[t]  <= M * epsilon_ch[t], name=f"charge_power_limit_{t}")
            m.addConstr(epsilon_dis[t] + epsilon_ch[t] <= 1, name=f"battery_state_{t}")

            # SoC update constraint
            m.addConstr(
                SoC[t] == (1-cf.ETA_LOSS)*SoC[t-1]
                    + cf.ETA_CH * Pch[t] * 1e3 * cf.interval*60/cf.E_ESS
                    - (1/cf.ETA_DCH) * Pdis[t] * 1e3 * cf.interval*60/cf.E_ESS,
                name=f"SoC_{t}"
            )
            
            # Heat balance
            m.addConstr(H_sub[t] == heat_demand_5min_forecast[t]*1e3 - H_1[t], name=f"heat_balance_{t}")

        # assess the deviation from optimal schedule
        dev_Pimp = P_imp_opt - Pimp
        dev_Pexp = P_exp_opt - Pexp # deiate from the optimal power transfer
        dev_SoC =  SoC_opt - SoC  # deviate from the optimal charging 

        # bathcworkload deviation 
        dev_LBW1 = L_BW[0,:] - LBW1_opt
        dev_LBW2 = L_BW[1,:] - LBW2_opt

        # dev_LBW2 = np.zeros(cf.STEP)
        # for t in range(cf.STEP):
        #     dev_LBW1[t] = L_BW[0,t] - LBW1_opt[t] 
        #     dev_LBW2[t] = L_BW[1,t] - LBW2_opt[t]

        # Declare objective function
        obj = 0

        # Linear energy cost part (exactly equals your abs-based expression)
        # delta_t * sum( p_buy[t]*Pimp[t] - p_sell[t]*Pexp[t] )
        obj += quicksum((cf.interval/60) * (p_buy_5min[t] * Pimp[t] - p_sell_5min[t] * Pexp[t]) for t in range(cf.STEP))
        
        # obj += quicksum(dev_Pimp[t]**2 + dev_Pexp[t]**2 + dev_SoC[t]**2 for t in range(cf.STEP))

        # Cost for substituting heat with gas boiler when waste heat is insufficient:
        # A * delta_t * sum(p_gas_5min[t] * (heat_demand[t] - H_1[t])^2 )
        obj += quicksum(stg1.mode * (cf.interval/60)*p_gas_5min[t] * (H_sub[t]*1e-3) + (1-stg1.mode) * (cf.interval/60) * p_gas_5min[t] * (heat_demand_5min_forecast[t]) for t in range(cf.STEP))

        m.setObjective(obj, GRB.MINIMIZE)
        m.setParam("InfUnbdInfo", 1)  # Distinguish infeasible/unbounded
        m.optimize()

        if m.Status == GRB.INFEASIBLE:
            print("Model infeasible -> computing IIS...")
            m.computeIIS()

            # Write files you can open in a text editor
            m.write("model_stg2.lp")      # full model in LP format
            m.write("infeasible_stg2.ilp")  # IIS in ILP format (minimal conflicting set)

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
            raise RuntimeError(f"Optimization stopped with status {m.Status} (INFEASIBLE). See infeasible_stg2.ilp for details.")
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
        
        global sol, sol_hour, flat_row
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
        
        # extract only the first 12 elements
        N = int(60 / cf.interval)
        sol_hour = {
            "Pimp":  sol["Pimp"][:N],
            "Pexp":  sol["Pexp"][:N],
            "H":     sol["H"][:N],
            "SoC":   sol["SoC"][:N],
            "L_BW1": sol["L_BW"][0, :N],
            "L_BW2": sol["L_BW"][1, :N],
            "A_DC":  sol["A_DC"][:N],
            "Pch":   sol["Pch"][:N],
            "Pdis":  sol["Pdis"][:N],
            "P_source": sol["P_source"][:N],
            "P_fan":    sol["P_fan"][:N],
            "P_cooling": sol["P_cooling"][:N],
            "TRCU": sol["TRCU"][:N],
            "QRCU": sol["QRCU"][:N],
            "PS1":  sol["PS1"][:N],
            "PS2":  sol["PS2"][:N],
            "Ti1":  sol["Ti"][0, :N],
            "Ti2":  sol["Ti"][1, :N],
            "To1":  sol["To"][0, :N],
            "To2":  sol["To"][1, :N],
            }
        

    for i in range(1, cf.STEP):
        energy_cost = (cf.interval/60) * np.sum(p_buy_5min[i] * sol["Pimp"] - p_sell_5min[i] * sol["Pexp"] + p_gas_5min[i]*(heat_demand_5min[i] - sol["H"]*1e-3))
        heat_pen    = np.sum( (cf.interval/60) * p_gas_5min[i] * (heat_demand_5min_forecast[i] - sol["H"]*1e-3)**2)

    print(f"\nOptimal objective: {m.obj_val:.4f}")
    print(f"  Energy cost term: {energy_cost:.4f}")
    print(f"  Heat penalty term: {heat_pen:.4f}")

    # store objective values based on mode
    if stg1.mode == 0:
        Single_Obj = m.obj_val
        Single_Energy_Cost = energy_cost
        Single_Heat_Penalty = heat_pen
    elif stg1.mode == 1:
        Multi_Obj = m.obj_val
        Multi_Energy_Cost = energy_cost
        Multi_Heat_Penalty = heat_pen

    for i in range(cf.NUMBER_OF_SERVERS):
        Ti[i] = sol["Ti"][i,int(60/cf.interval)-1]
        To[i] = sol["To"][i,int(60/cf.interval)-1]

        # export the final states for the next optimisation horizon
    final_states = {
        "Ti_final": Ti,
        "To_final": To,
        "SoC_final": sol["SoC"][int(60/cf.interval)-1],
        "TRCU_final": sol["TRCU"][int(60/cf.interval)-1],
        "QRCU_final": sol["QRCU"][int(60/cf.interval)-1],
        "PS1_final": sol["PS1"][int(60/cf.interval)-1],
        "PS2_final": sol["PS2"][int(60/cf.interval)-1],
    }

    import os

    csv_path = "states.csv"
    csv_path_con = "stage2_hourly_results.csv"  # to store control actions
    
    N = int(60/cf.interval)
    
    # data frame for 12 rows in 1 hour
    df_hour = pd.DataFrame(sol_hour)
    df_hour["hour"] = mf.CURRENT_HOUR
    df_hour["interval"] = range(N)
    df_hour["t_global"] = mf.CURRENT_HOUR * N + df_hour["interval"]

    # -- Convert first 12 steps of results into flat format --
    flat_row = {key: sol_hour[key].tolist() for key in sol_hour}
    row_df = pd.DataFrame([final_states]).iloc[0]
    
    # -------------------- Initialise CSV files if file doesnt exist --------------------
    # Final states CSV (one row per hour)
    if not os.path.isfile(csv_path):
        df = pd.DataFrame(None, index=range(cf.HOURS), columns=final_states.keys())
        df.to_csv(csv_path, index=False)
    else:
        df = pd.read_csv(csv_path)
    # Final states
    df.loc[mf.CURRENT_HOUR] = row_df
    df.to_csv(csv_path, index=False)
    
    # Control actions CSV (multiple rows: 12 rows per hour)
    if not os.path.isfile(csv_path_con):
        # Write header on first creation
        df_hour.to_csv(csv_path_con, index=False)
    else:
        # Load existing file
        df_con = pd.read_csv(csv_path_con)

    # Remove any old rows for this hour
    df_con = df_con[df_con["hour"] != mf.CURRENT_HOUR]

    # Append the NEW 12 rows
    df_con = pd.concat([df_con, df_hour], ignore_index=True)

    # Save back
    df_con.to_csv(csv_path_con, index=False)


    

#%% Supply and demand 
def plot():
    supply = P_solar_5min_forecast[0:cf.STEP] + P_wind_5min_forecast[0:cf.STEP] + sol["Pdis"]  + sol["Pimp"]

    demand = ff.server_consumption(1.5, sol["A_DC"], np.sum(sol["L_BW"], axis=0), cf.L_RATE, cf.P_IDLE, cf.P_PEAK) \
            + ff.server_consumption(1.5, sol["A_DC"], L_DC_5min_forecast[mf.CURRENT_HOUR:mf.CURRENT_HOUR+cf.STEP] - np.sum(sol["L_BW"], axis=0), cf.L_RATE, cf.P_IDLE, cf.P_PEAK)\
            + sol["P_cooling"]*1e-3 + sol["Pexp"] + sol["Pch"]

    # Time steps for plots
    t = np.arange(cf.STEP)
    y = [
        P_solar_5min_forecast[0:cf.STEP],
        P_wind_5min_forecast[0:cf.STEP],
        sol["Pdis"],
        sol["Pimp"]
    ]

    labels = ["Solar Power", "Wind Power", "Battery Discharge", "Grid Import"]
    colors = ["gold", "skyblue", "lightcoral", "violet"]

    # Print to indicate iteration 
    print("___________________________________current hour:", mf.CURRENT_HOUR, "___________________________")

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
    ff.plot_timeseries_multi(t, [P_imp_opt, P_exp_opt, sol["Pimp"], sol["Pexp"]], ["stg imp", "stg1 exp2","Import", "Export"], "Import/Export Split", ylabel="kW")
    ff.plot_timeseries_multi(t, [heat_demand_5min[:cf.STEP], sol["H"]*1e-3], ["Heat Demand", "Recovered Heat"], "Heat Demand vs Recovered Heat", ylabel="kW(th)")
    ff.plot_timeseries_multi(t, [p_buy_5min[:cf.STEP], p_sell_5min[:cf.STEP]], ["Buy price", "Sell price"], "Electricity Prices", ylabel="£/kWh")
    ff.plot_timeseries_multi(t, [P_bat_ch_opt, P_bat_dis_opt, sol["Pch"], sol["Pdis"]], ["stg1 ch", "stg1 dis","Charge", "Discharge"], "Battery Charge/Discharge Power", ylabel="kW")
    ff.plot_timeseries_multi(t, [SoC_opt, sol["SoC"]], ["stg1 SoC","State of Charge"], "SoC Over Time", ylabel="SoC")
    ff.plot_timeseries_multi(t, [LBW1_opt+LBW2_opt, np.sum(sol["L_BW"], axis=0), L_IW_5min_forecast[:cf.STEP]], ["stg1 LBW","Batch Workload", "Interactive Workload"], "Data Centre Load Profile", ylabel="Load (requests/hour)")
    ff.plot_timeseries_multi(t, [sol["A_DC"]], ["Active Servers"], "Fraction of Active Servers Over Time", ylabel="Fraction")


# %%

# %%
def iterate():
    # Update the CURRENT_HOUR for the next iteration, this also update the values in Monitored_file.py
    print("current hour:", mf.CURRENT_HOUR)

    # %%
    mf.CURRENT_HOUR += 1
    print("next hour:", mf.CURRENT_HOUR)

# %%

def plot_results(name="file_name", hours=None, plots="all"):
    """
    Plot results for selected hours and plot types.

    Parameters
    ----------
    name  : str
        CSV file name containing 5-min interval results.
    hours : int, list, or range
        Which hours to plot. If multiple hours → merged continuous plot.
    plots : str or list
        Which plots to show. Options:
        "supply", "demand_stack", "supply_demand",
        "grid", "heat", "battery", "soc",
        "workload", "servers", or "all".
    """

    # Load all 5-min results
    df = pd.read_csv(name)

    # Number of 5-min intervals per hour
    N = int(60 / cf.interval)

    # -------------------------------
    # Process "hours" argument
    # -------------------------------
    if hours is None:
        hours = [mf.CURRENT_HOUR]

    if isinstance(hours, int):
        hours = [hours]

    hours = sorted([h for h in hours if 0 <= h < cf.HOURS])

    # -------------------------------
    # Process "plots" argument
    # -------------------------------
    if isinstance(plots, str):
        if plots == "all":
            plots = [
                "supply", "demand_stack", "supply_demand",
                "grid", "heat", "battery", "soc",
                "workload", "servers"
            ]
        else:
            plots = [plots]

    # -------------------------------
    # SELECT THE DATA ACROSS HOURS
    # -------------------------------
    df_sel = df[df["hour"].isin(hours)].reset_index(drop=True)

    # Time axis auto scales with number of rows selected
    t = np.arange(len(df_sel))
    xmax = len(t) - 1     # automatic x-axis right boundary

    # Extract signals
    Pimp = df_sel["Pimp"].values
    Pexp = df_sel["Pexp"].values
    Pdis = df_sel["Pdis"].values
    Pch  = df_sel["Pch"].values
    H    = df_sel["H"].values
    SoC  = df_sel["SoC"].values
    A_DC = df_sel["A_DC"].values
    L_BW1 = df_sel["L_BW1"].values
    L_BW2 = df_sel["L_BW2"].values
    cool = df_sel["P_cooling"].values * 1e-3  # convert W→kW

    # Build forecast slices for the same merged hours
    idx = []
    for h in hours:
        idx.extend(range(h * N, h * N + N))

    solar = P_solar_5min_forecast[idx]
    wind  = P_wind_5min_forecast[idx]
    L_IW  = L_IW_5min_forecast[idx]

    L_total = L_BW1 + L_BW2 + L_IW

    # Total loads
    P_IT = ff.server_consumption(
        1.5, A_DC, L_total, cf.L_RATE, cf.P_IDLE, cf.P_PEAK
    )
    supply = solar + wind + Pdis + Pimp
    demand = P_IT + cool + Pexp + Pch

    print(f"_____ PLOTTING HOURS {hours} (merged timeline) _____")

    # ----------------------------------------------------
    # SUPPLY STACKPLOT
    # ----------------------------------------------------
    if "supply" in plots:
        plt.figure(figsize=(10, 4))
        plt.stackplot(
            t,
            [solar, wind, Pdis, Pimp],
            labels=["Solar", "Wind", "Battery Discharge", "Grid Import"],
            colors=["gold", "skyblue", "lightcoral", "violet"],
            alpha=0.8
        )
        plt.title(f"Supply Mix – Hours {hours}")
        plt.xlabel("5-min Interval Index")
        plt.ylabel("Power (kW)")
        plt.legend()
        plt.grid(alpha=0.3)
        plt.xlim(0, xmax)
        plt.tight_layout()
        plt.show()

    # ----------------------------------------------------
    # DEMAND STACKPLOT
    # ----------------------------------------------------
    if "demand_stack" in plots:
        plt.figure(figsize=(10, 4))
        plt.stackplot(
            t,
            [P_IT, cool, Pch, Pexp],
            labels=["IT Load", "Cooling", "Charging", "Export"],
            colors=["dodgerblue", "turquoise", "orange", "purple"],
            alpha=0.8
        )
        plt.title(f"Demand Breakdown – Hours {hours}")
        plt.xlabel("5-min Interval Index")
        plt.ylabel("Power (kW)")
        plt.legend()
        plt.grid(alpha=0.3)
        plt.xlim(0, xmax)
        plt.tight_layout()
        plt.show()

    # ----------------------------------------------------
    # SUPPLY vs DEMAND
    # ----------------------------------------------------
    if "supply_demand" in plots:
        ff.plot_timeseries_multi(
            t, [supply, demand],
            ["Supply", "Demand"],
            f"Supply vs Demand – Hours {hours}",
            ylabel="kW"
        )
        plt.xlim(0, xmax)

    # ----------------------------------------------------
    # GRID IMPORT / EXPORT
    # ----------------------------------------------------
    if "grid" in plots:
        ff.plot_timeseries_multi(
            t, [Pimp, Pexp],
            ["Import", "Export"],
            f"Grid Power – Hours {hours}",
            ylabel="kW"
        )
        plt.xlim(0, xmax)

    # ----------------------------------------------------
    # HEAT RECOVERY
    # ----------------------------------------------------
    if "heat" in plots:
        ff.plot_timeseries_multi(
            t, [H * 1e-3],
            ["Recovered Heat"],
            f"Recovered Heat – Hours {hours}",
            ylabel="kW(th)"
        )
        plt.xlim(0, xmax)

    # ----------------------------------------------------
    # BATTERY OPERATION
    # ----------------------------------------------------
    if "battery" in plots:
        ff.plot_timeseries_multi(
            t, [Pch, Pdis],
            ["Charge", "Discharge"],
            f"Battery Operation – Hours {hours}",
            ylabel="kW"
        )
        plt.xlim(0, xmax)

    # ----------------------------------------------------
    # STATE OF CHARGE
    # ----------------------------------------------------
    if "soc" in plots:
        ff.plot_timeseries_multi(
            t, [SoC],
            ["State of Charge"],
            f"SoC – Hours {hours}",
            ylabel="SoC"
        )
        plt.xlim(0, xmax)

    # ----------------------------------------------------
    # WORKLOAD
    # ----------------------------------------------------
    if "workload" in plots:
        ff.plot_timeseries_multi(
            t, [L_BW1 + L_BW2, L_IW],
            ["Batch Load", "Interactive Load"],
            f"Workload – Hours {hours}",
            ylabel="Requests/hour"
        )
        plt.xlim(0, xmax)

    # ----------------------------------------------------
    # ACTIVE SERVERS
    # ----------------------------------------------------
    if "servers" in plots:
        ff.plot_timeseries_multi(
            t, [A_DC],
            ["Active Servers"],
            f"Server Activation – Hours {hours}",
            ylabel="Fraction Active"
        )
        plt.xlim(0, xmax)
