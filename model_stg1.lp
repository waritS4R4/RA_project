\ Model Upper_Layer_Optimisation
\ LP format - for model browsing. Use MPS format to capture full model detail.
\ Signature: 0x62c92adfdebf107a
Minimize
  0 U[2,23] + 0 U[3,23] + 0 previous_LBW[1] + 0 previous_LBW[2]
   + 0 previous_LBW[3] + 0 previous_LBW[4] + 0 previous_LBW[5]
   + 0 previous_LBW[6] + 0 previous_LBW[7] + 0 previous_LBW[8]
   + 0 previous_LBW[9] + 0 previous_LBW[10] + 0 previous_LBW[11]
   + 0 previous_LBW[12] + 0 previous_LBW[13] + 0 previous_LBW[14]
   + 0 previous_LBW[15] + 0 previous_LBW[16] + 0 previous_LBW[17]
   + 0 previous_LBW[18] + 0 previous_LBW[19] + 0 previous_LBW[20]
   + 0 previous_LBW[21] + 0 previous_LBW[22] + 0 previous_LBW[23]
   + 5.58833e-05 H_sub[0] + 5.58833e-05 H_sub[1] + 5.58833e-05 H_sub[2]
   + 5.58833e-05 H_sub[3] + 5.58833e-05 H_sub[4] + 5.58833e-05 H_sub[5]
   + 5.58833e-05 H_sub[6] + 5.58833e-05 H_sub[7] + 5.58833e-05 H_sub[8]
   + 5.58833e-05 H_sub[9] + 5.58833e-05 H_sub[10] + 5.58833e-05 H_sub[11]
   + 5.58833e-05 H_sub[12] + 5.58833e-05 H_sub[13] + 5.58833e-05 H_sub[14]
   + 5.58833e-05 H_sub[15] + 5.58833e-05 H_sub[16] + 5.58833e-05 H_sub[17]
   + 5.58833e-05 H_sub[18] + 5.58833e-05 H_sub[19] + 5.58833e-05 H_sub[20]
   + 5.58833e-05 H_sub[21] + 5.58833e-05 H_sub[22] + 5.58833e-05 H_sub[23]
   + 0 H_1[0] + 0.1758 Pimp[0] + 0.1629 Pimp[1] + 0.1587 Pimp[2]
   + 0.1599 Pimp[3] + 0.16 Pimp[4] + 0.1522 Pimp[5] + 0.2129 Pimp[6]
   + 0.2343 Pimp[7] + 0.2069 Pimp[8] + 0.171 Pimp[9] + 0.1649 Pimp[10]
   + 0.1605 Pimp[11] + 0.1614 Pimp[12] + 0.16 Pimp[13] + 0.1531 Pimp[14]
   + 0.1546 Pimp[15] + 0.2964 Pimp[16] + 0.3295 Pimp[17] + 0.3464 Pimp[18]
   + 0.2474 Pimp[19] + 0.2414 Pimp[20] + 0.2188 Pimp[21] + 0.175 Pimp[22]
   + 0.1968 Pimp[23] - 0.0834 Pexp[0] - 0.0879 Pexp[1] - 0.0834 Pexp[2]
   - 0.0696 Pexp[3] - 0.0699 Pexp[4] - 0.0747 Pexp[5] - 0.0863 Pexp[6]
   - 0.0994 Pexp[7] - 0.0979 Pexp[8] - 0.0884 Pexp[9] - 0.0708 Pexp[10]
   - 0.0551 Pexp[11] - 0.0361 Pexp[12] - 0.024 Pexp[13] - 0.0128 Pexp[14]
   - 0.0192 Pexp[15] - 0.1086 Pexp[16] - 0.1304 Pexp[17] - 0.1407 Pexp[18]
   - 0.0947 Pexp[19] - 0.1007 Pexp[20] - 0.0999 Pexp[21] - 0.0902 Pexp[22]
   - 0.0837 Pexp[23] + 0 Pch[0] + 0 Pdis[0] + 0 epsilon_ch[0]
   + 0 epsilon_dis[0] + 0 P_source[0] + 0 P_fan[0] + 0 P_cooling[0]
   + 0 Avg_T0[0] + 0 Avg_T0[1] + 0 Avg_T0[2] + 0 Avg_T0[3] + 0 Avg_T0[4]
   + 0 Avg_T0[5] + 0 Avg_T0[6] + 0 Avg_T0[7] + 0 Avg_T0[8] + 0 Avg_T0[9]
   + 0 Avg_T0[10] + 0 Avg_T0[11] + 0 Avg_T0[12] + 0 Avg_T0[13]
   + 0 Avg_T0[14] + 0 Avg_T0[15] + 0 Avg_T0[16] + 0 Avg_T0[17]
   + 0 Avg_T0[18] + 0 Avg_T0[19] + 0 Avg_T0[20] + 0 Avg_T0[21]
   + 0 Avg_T0[22] + 0 Avg_T0[23]
Subject To
 initial_states_X_1[0]: rack_1[0,0] = 20
 initial_states_X_1[1]: rack_1[1,0] = 20
 initial_states_X_1[2]: rack_1[2,0] = 38
 initial_states_X_1[3]: rack_1[3,0] = 38
 initial_states_SoC: SoC[0] = 0.8
 initial_inputs_U_0[0]: U[0,0] = 25
 initial_inputs_U_0[1]: U[1,0] = 0.05
 initial_inputs_U_0[2]: U[2,0] = 0
 initial_inputs_U_0[3]: U[3,0] = 0
 initial_total_schedule_BW: previous_LBW[0] = 0
 R10: L_BW[0,0] = 0
 R11: L_BW[1,0] = 0
 total_load_0: - L_BW[0,0] - L_BW[1,0] + L[0] = 300
 pdc_def_0: - 0.1005 A_DC[0] - 0.00133333333333333 L[0] + P_dc[0] = 0
 total_load_1: - L_BW[0,1] - L_BW[1,1] + L[1] = 280
 pdc_def_1: - 0.1005 A_DC[1] - 0.00133333333333333 L[1] + P_dc[1] = 0
 total_load_2: - L_BW[0,2] - L_BW[1,2] + L[2] = 260
 pdc_def_2: - 0.1005 A_DC[2] - 0.00133333333333333 L[2] + P_dc[2] = 0
 total_load_3: - L_BW[0,3] - L_BW[1,3] + L[3] = 250
 pdc_def_3: - 0.1005 A_DC[3] - 0.00133333333333333 L[3] + P_dc[3] = 0
 total_load_4: - L_BW[0,4] - L_BW[1,4] + L[4] = 260
 pdc_def_4: - 0.1005 A_DC[4] - 0.00133333333333333 L[4] + P_dc[4] = 0
 total_load_5: - L_BW[0,5] - L_BW[1,5] + L[5] = 350
 pdc_def_5: - 0.1005 A_DC[5] - 0.00133333333333333 L[5] + P_dc[5] = 0
 total_load_6: - L_BW[0,6] - L_BW[1,6] + L[6] = 600
 pdc_def_6: - 0.1005 A_DC[6] - 0.00133333333333333 L[6] + P_dc[6] = 0
 total_load_7: - L_BW[0,7] - L_BW[1,7] + L[7] = 800
 pdc_def_7: - 0.1005 A_DC[7] - 0.00133333333333333 L[7] + P_dc[7] = 0
 total_load_8: - L_BW[0,8] - L_BW[1,8] + L[8] = 1000
 pdc_def_8: - 0.1005 A_DC[8] - 0.00133333333333333 L[8] + P_dc[8] = 0
 total_load_9: - L_BW[0,9] - L_BW[1,9] + L[9] = 1100
 pdc_def_9: - 0.1005 A_DC[9] - 0.00133333333333333 L[9] + P_dc[9] = 0
 total_load_10: - L_BW[0,10] - L_BW[1,10] + L[10] = 1150
 pdc_def_10: - 0.1005 A_DC[10] - 0.00133333333333333 L[10] + P_dc[10] = 0
 total_load_11: - L_BW[0,11] - L_BW[1,11] + L[11] = 1200
 pdc_def_11: - 0.1005 A_DC[11] - 0.00133333333333333 L[11] + P_dc[11] = 0
 total_load_12: - L_BW[0,12] - L_BW[1,12] + L[12] = 1200
 pdc_def_12: - 0.1005 A_DC[12] - 0.00133333333333333 L[12] + P_dc[12] = 0
 total_load_13: - L_BW[0,13] - L_BW[1,13] + L[13] = 1150
 pdc_def_13: - 0.1005 A_DC[13] - 0.00133333333333333 L[13] + P_dc[13] = 0
 total_load_14: - L_BW[0,14] - L_BW[1,14] + L[14] = 1100
 pdc_def_14: - 0.1005 A_DC[14] - 0.00133333333333333 L[14] + P_dc[14] = 0
 total_load_15: - L_BW[0,15] - L_BW[1,15] + L[15] = 1000
 pdc_def_15: - 0.1005 A_DC[15] - 0.00133333333333333 L[15] + P_dc[15] = 0
 total_load_16: - L_BW[0,16] - L_BW[1,16] + L[16] = 900
 pdc_def_16: - 0.1005 A_DC[16] - 0.00133333333333333 L[16] + P_dc[16] = 0
 total_load_17: - L_BW[0,17] - L_BW[1,17] + L[17] = 800
 pdc_def_17: - 0.1005 A_DC[17] - 0.00133333333333333 L[17] + P_dc[17] = 0
 total_load_18: - L_BW[0,18] - L_BW[1,18] + L[18] = 700
 pdc_def_18: - 0.1005 A_DC[18] - 0.00133333333333333 L[18] + P_dc[18] = 0
 total_load_19: - L_BW[0,19] - L_BW[1,19] + L[19] = 600
 pdc_def_19: - 0.1005 A_DC[19] - 0.00133333333333333 L[19] + P_dc[19] = 0
 total_load_20: - L_BW[0,20] - L_BW[1,20] + L[20] = 500
 pdc_def_20: - 0.1005 A_DC[20] - 0.00133333333333333 L[20] + P_dc[20] = 0
 total_load_21: - L_BW[0,21] - L_BW[1,21] + L[21] = 400
 pdc_def_21: - 0.1005 A_DC[21] - 0.00133333333333333 L[21] + P_dc[21] = 0
 total_load_22: - L_BW[0,22] - L_BW[1,22] + L[22] = 350
 pdc_def_22: - 0.1005 A_DC[22] - 0.00133333333333333 L[22] + P_dc[22] = 0
 total_load_23: - L_BW[0,23] - L_BW[1,23] + L[23] = 320
 pdc_def_23: - 0.1005 A_DC[23] - 0.00133333333333333 L[23] + P_dc[23] = 0
 cumulative_batch_feasibility_0: L_BW[0,0] + L_BW[1,0] <= 300
 active_server_for_BW: - L_BW[0,0] - L_BW[1,0] + 300 A_DC[0] >= 0
 cumulative_batch_feasibility_1: L_BW[0,0] + L_BW[0,1] + L_BW[1,0]
   + L_BW[1,1] <= 570
 active_server_for_BW: - L_BW[0,1] - L_BW[1,1] + 300 A_DC[1] >= 0
 cumulative_batch_feasibility_2: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] <= 830
 active_server_for_BW: - L_BW[0,2] - L_BW[1,2] + 300 A_DC[2] >= 0
 cumulative_batch_feasibility_3: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] <= 1080
 active_server_for_BW: - L_BW[0,3] - L_BW[1,3] + 300 A_DC[3] >= 0
 cumulative_batch_feasibility_4: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] + L_BW[1,3]
   + L_BW[1,4] <= 1340
 active_server_for_BW: - L_BW[0,4] - L_BW[1,4] + 300 A_DC[4] >= 0
 cumulative_batch_feasibility_5: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[1,0] + L_BW[1,1] + L_BW[1,2]
   + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] <= 1590
 active_server_for_BW: - L_BW[0,5] - L_BW[1,5] + 300 A_DC[5] >= 0
 cumulative_batch_feasibility_6: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[1,0] + L_BW[1,1]
   + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6] <= 1790
 active_server_for_BW: - L_BW[0,6] - L_BW[1,6] + 300 A_DC[6] >= 0
 cumulative_batch_feasibility_7: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[1,0]
   + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6]
   + L_BW[1,7] <= 1990
 active_server_for_BW: - L_BW[0,7] - L_BW[1,7] + 300 A_DC[7] >= 0
 cumulative_batch_feasibility_8: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5]
   + L_BW[1,6] + L_BW[1,7] + L_BW[1,8] <= 2190
 active_server_for_BW: - L_BW[0,8] - L_BW[1,8] + 300 A_DC[8] >= 0
 cumulative_batch_feasibility_9: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4]
   + L_BW[1,5] + L_BW[1,6] + L_BW[1,7] + L_BW[1,8] + L_BW[1,9] <= 2390
 active_server_for_BW: - L_BW[0,9] - L_BW[1,9] + 300 A_DC[9] >= 0
 cumulative_batch_feasibility_10: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] + L_BW[1,3]
   + L_BW[1,4] + L_BW[1,5] + L_BW[1,6] + L_BW[1,7] + L_BW[1,8] + L_BW[1,9]
   + L_BW[1,10] <= 2640
 active_server_for_BW: - L_BW[0,10] - L_BW[1,10] + 300 A_DC[10] >= 0
 cumulative_batch_feasibility_11: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[1,0] + L_BW[1,1]
   + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6] + L_BW[1,7]
   + L_BW[1,8] + L_BW[1,9] + L_BW[1,10] + L_BW[1,11] <= 2940
 active_server_for_BW: - L_BW[0,11] - L_BW[1,11] + 300 A_DC[11] >= 0
 cumulative_batch_feasibility_12: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[1,0]
   + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6]
   + L_BW[1,7] + L_BW[1,8] + L_BW[1,9] + L_BW[1,10] + L_BW[1,11]
   + L_BW[1,12] <= 3240
 active_server_for_BW: - L_BW[0,12] - L_BW[1,12] + 300 A_DC[12] >= 0
 cumulative_batch_feasibility_13: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5]
   + L_BW[1,6] + L_BW[1,7] + L_BW[1,8] + L_BW[1,9] + L_BW[1,10]
   + L_BW[1,11] + L_BW[1,12] + L_BW[1,13] <= 3540
 active_server_for_BW: - L_BW[0,13] - L_BW[1,13] + 300 A_DC[13] >= 0
 cumulative_batch_feasibility_14: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[0,14] + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4]
   + L_BW[1,5] + L_BW[1,6] + L_BW[1,7] + L_BW[1,8] + L_BW[1,9] + L_BW[1,10]
   + L_BW[1,11] + L_BW[1,12] + L_BW[1,13] + L_BW[1,14] <= 3840
 active_server_for_BW: - L_BW[0,14] - L_BW[1,14] + 300 A_DC[14] >= 0
 cumulative_batch_feasibility_15: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[0,14] + L_BW[0,15] + L_BW[1,0] + L_BW[1,1] + L_BW[1,2]
   + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6] + L_BW[1,7] + L_BW[1,8]
   + L_BW[1,9] + L_BW[1,10] + L_BW[1,11] + L_BW[1,12] + L_BW[1,13]
   + L_BW[1,14] + L_BW[1,15] <= 4190
 active_server_for_BW: - L_BW[0,15] - L_BW[1,15] + 300 A_DC[15] >= 0
 cumulative_batch_feasibility_16: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[0,14] + L_BW[0,15] + L_BW[0,16] + L_BW[1,0] + L_BW[1,1]
   + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6] + L_BW[1,7]
   + L_BW[1,8] + L_BW[1,9] + L_BW[1,10] + L_BW[1,11] + L_BW[1,12]
   + L_BW[1,13] + L_BW[1,14] + L_BW[1,15] + L_BW[1,16] <= 4590
 active_server_for_BW: - L_BW[0,16] - L_BW[1,16] + 300 A_DC[16] >= 0
 cumulative_batch_feasibility_17: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[0,14] + L_BW[0,15] + L_BW[0,16] + L_BW[0,17] + L_BW[1,0]
   + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6]
   + L_BW[1,7] + L_BW[1,8] + L_BW[1,9] + L_BW[1,10] + L_BW[1,11]
   + L_BW[1,12] + L_BW[1,13] + L_BW[1,14] + L_BW[1,15] + L_BW[1,16]
   + L_BW[1,17] <= 5040
 active_server_for_BW: - L_BW[0,17] - L_BW[1,17] + 300 A_DC[17] >= 0
 cumulative_batch_feasibility_18: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[0,14] + L_BW[0,15] + L_BW[0,16] + L_BW[0,17] + L_BW[0,18]
   + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5]
   + L_BW[1,6] + L_BW[1,7] + L_BW[1,8] + L_BW[1,9] + L_BW[1,10]
   + L_BW[1,11] + L_BW[1,12] + L_BW[1,13] + L_BW[1,14] + L_BW[1,15]
   + L_BW[1,16] + L_BW[1,17] + L_BW[1,18] <= 5540
 active_server_for_BW: - L_BW[0,18] - L_BW[1,18] + 300 A_DC[18] >= 0
 cumulative_batch_feasibility_19: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[0,14] + L_BW[0,15] + L_BW[0,16] + L_BW[0,17] + L_BW[0,18]
   + L_BW[0,19] + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4]
   + L_BW[1,5] + L_BW[1,6] + L_BW[1,7] + L_BW[1,8] + L_BW[1,9] + L_BW[1,10]
   + L_BW[1,11] + L_BW[1,12] + L_BW[1,13] + L_BW[1,14] + L_BW[1,15]
   + L_BW[1,16] + L_BW[1,17] + L_BW[1,18] + L_BW[1,19] <= 6040
 active_server_for_BW: - L_BW[0,19] - L_BW[1,19] + 300 A_DC[19] >= 0
 cumulative_batch_feasibility_20: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[0,14] + L_BW[0,15] + L_BW[0,16] + L_BW[0,17] + L_BW[0,18]
   + L_BW[0,19] + L_BW[0,20] + L_BW[1,0] + L_BW[1,1] + L_BW[1,2]
   + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6] + L_BW[1,7] + L_BW[1,8]
   + L_BW[1,9] + L_BW[1,10] + L_BW[1,11] + L_BW[1,12] + L_BW[1,13]
   + L_BW[1,14] + L_BW[1,15] + L_BW[1,16] + L_BW[1,17] + L_BW[1,18]
   + L_BW[1,19] + L_BW[1,20] <= 6540
 active_server_for_BW: - L_BW[0,20] - L_BW[1,20] + 300 A_DC[20] >= 0
 cumulative_batch_feasibility_21: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[0,14] + L_BW[0,15] + L_BW[0,16] + L_BW[0,17] + L_BW[0,18]
   + L_BW[0,19] + L_BW[0,20] + L_BW[0,21] + L_BW[1,0] + L_BW[1,1]
   + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6] + L_BW[1,7]
   + L_BW[1,8] + L_BW[1,9] + L_BW[1,10] + L_BW[1,11] + L_BW[1,12]
   + L_BW[1,13] + L_BW[1,14] + L_BW[1,15] + L_BW[1,16] + L_BW[1,17]
   + L_BW[1,18] + L_BW[1,19] + L_BW[1,20] + L_BW[1,21] <= 7040
 active_server_for_BW: - L_BW[0,21] - L_BW[1,21] + 300 A_DC[21] >= 0
 cumulative_batch_feasibility_22: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[0,14] + L_BW[0,15] + L_BW[0,16] + L_BW[0,17] + L_BW[0,18]
   + L_BW[0,19] + L_BW[0,20] + L_BW[0,21] + L_BW[0,22] + L_BW[1,0]
   + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6]
   + L_BW[1,7] + L_BW[1,8] + L_BW[1,9] + L_BW[1,10] + L_BW[1,11]
   + L_BW[1,12] + L_BW[1,13] + L_BW[1,14] + L_BW[1,15] + L_BW[1,16]
   + L_BW[1,17] + L_BW[1,18] + L_BW[1,19] + L_BW[1,20] + L_BW[1,21]
   + L_BW[1,22] <= 7490
 active_server_for_BW: - L_BW[0,22] - L_BW[1,22] + 300 A_DC[22] >= 0
 cumulative_batch_feasibility_23: L_BW[0,0] + L_BW[0,1] + L_BW[0,2]
   + L_BW[0,3] + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8]
   + L_BW[0,9] + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13]
   + L_BW[0,14] + L_BW[0,15] + L_BW[0,16] + L_BW[0,17] + L_BW[0,18]
   + L_BW[0,19] + L_BW[0,20] + L_BW[0,21] + L_BW[0,22] + L_BW[0,23]
   + L_BW[1,0] + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5]
   + L_BW[1,6] + L_BW[1,7] + L_BW[1,8] + L_BW[1,9] + L_BW[1,10]
   + L_BW[1,11] + L_BW[1,12] + L_BW[1,13] + L_BW[1,14] + L_BW[1,15]
   + L_BW[1,16] + L_BW[1,17] + L_BW[1,18] + L_BW[1,19] + L_BW[1,20]
   + L_BW[1,21] + L_BW[1,22] + L_BW[1,23] <= 7870
 active_server_for_BW: - L_BW[0,23] - L_BW[1,23] + 300 A_DC[23] >= 0
 end_of_day_workload: L_BW[0,0] + L_BW[0,1] + L_BW[0,2] + L_BW[0,3]
   + L_BW[0,4] + L_BW[0,5] + L_BW[0,6] + L_BW[0,7] + L_BW[0,8] + L_BW[0,9]
   + L_BW[0,10] + L_BW[0,11] + L_BW[0,12] + L_BW[0,13] + L_BW[0,14]
   + L_BW[0,15] + L_BW[0,16] + L_BW[0,17] + L_BW[0,18] + L_BW[0,19]
   + L_BW[0,20] + L_BW[0,21] + L_BW[0,22] + L_BW[0,23] + L_BW[1,0]
   + L_BW[1,1] + L_BW[1,2] + L_BW[1,3] + L_BW[1,4] + L_BW[1,5] + L_BW[1,6]
   + L_BW[1,7] + L_BW[1,8] + L_BW[1,9] + L_BW[1,10] + L_BW[1,11]
   + L_BW[1,12] + L_BW[1,13] + L_BW[1,14] + L_BW[1,15] + L_BW[1,16]
   + L_BW[1,17] + L_BW[1,18] + L_BW[1,19] + L_BW[1,20] + L_BW[1,21]
   + L_BW[1,22] + L_BW[1,23] = 7870
 A_DC_1: 300 A_DC[1] >= 280
 qos_delay_1: 240 A_DC[1] <= 280
 A_DC_2: 300 A_DC[2] >= 260
 qos_delay_2: 240 A_DC[2] <= 260
 A_DC_3: 300 A_DC[3] >= 250
 qos_delay_3: 240 A_DC[3] <= 250
 A_DC_4: 300 A_DC[4] >= 260
 qos_delay_4: 240 A_DC[4] <= 260
 A_DC_5: 300 A_DC[5] >= 350
 qos_delay_5: 240 A_DC[5] <= 350
 A_DC_6: 300 A_DC[6] >= 600
 qos_delay_6: 240 A_DC[6] <= 600
 A_DC_7: 300 A_DC[7] >= 800
 qos_delay_7: 240 A_DC[7] <= 800
 A_DC_8: 300 A_DC[8] >= 1000
 qos_delay_8: 240 A_DC[8] <= 1000
 A_DC_9: 300 A_DC[9] >= 1100
 qos_delay_9: 240 A_DC[9] <= 1100
 A_DC_10: 300 A_DC[10] >= 1150
 qos_delay_10: 240 A_DC[10] <= 1150
 A_DC_11: 300 A_DC[11] >= 1200
 qos_delay_11: 240 A_DC[11] <= 1200
 A_DC_12: 300 A_DC[12] >= 1200
 qos_delay_12: 240 A_DC[12] <= 1200
 A_DC_13: 300 A_DC[13] >= 1150
 qos_delay_13: 240 A_DC[13] <= 1150
 A_DC_14: 300 A_DC[14] >= 1100
 qos_delay_14: 240 A_DC[14] <= 1100
 A_DC_15: 300 A_DC[15] >= 1000
 qos_delay_15: 240 A_DC[15] <= 1000
 A_DC_16: 300 A_DC[16] >= 900
 qos_delay_16: 240 A_DC[16] <= 900
 A_DC_17: 300 A_DC[17] >= 800
 qos_delay_17: 240 A_DC[17] <= 800
 A_DC_18: 300 A_DC[18] >= 700
 qos_delay_18: 240 A_DC[18] <= 700
 A_DC_19: 300 A_DC[19] >= 600
 qos_delay_19: 240 A_DC[19] <= 600
 A_DC_20: 300 A_DC[20] >= 500
 qos_delay_20: 240 A_DC[20] <= 500
 A_DC_21: 300 A_DC[21] >= 400
 qos_delay_21: 240 A_DC[21] <= 400
 A_DC_22: 300 A_DC[22] >= 350
 qos_delay_22: 240 A_DC[22] <= 350
 A_DC_23: 300 A_DC[23] >= 320
 qos_delay_23: 240 A_DC[23] <= 320
 PS1_1: U[2,0] - 1.333333333333333 L_BW[0,1] - 100.5 A_DC[0] = 200
 PS2_1: U[3,0] - 1.333333333333333 L_BW[1,1] - 100.5 A_DC[0] = 200
 temp_dynamics_X_1_1[0]: rack_1[0,1] - 8.2918739635157504e-04 U[0,0]
   - 0.9121061359867327 U[1,0] - 0.0071198776435842 U[2,0] = 0
 temp_dynamics_X_1_1[1]: rack_1[1,1] - 8.2918739635157504e-04 U[0,0]
   - 0.9121061359867327 U[1,0] - 0.0071198776435842 U[3,0] = 0
 temp_dynamics_X_1_1[2]: rack_1[2,1] - 8.2918739635157504e-04 U[0,0]
   - 0.9121061359867327 U[1,0] - 0.0188398408428998 U[2,0] = 0
 temp_dynamics_X_1_1[3]: rack_1[3,1] - 8.2918739635157504e-04 U[0,0]
   - 0.9121061359867327 U[1,0] - 0.0188398408428998 U[3,0] = 0
 avg_TRCU_1[0]: - U[1,1] + Avg_TRCU[0] = 0
 avg_TRCU_1[1]: - U[1,1] + Avg_TRCU[1] = 0
 avg_TRCU_1[2]: - U[1,1] + Avg_TRCU[2] = 0
 avg_TRCU_1[3]: - U[1,1] + Avg_TRCU[3] = 0
 avg_TRCU_1[4]: - U[1,1] + Avg_TRCU[4] = 0
 avg_TRCU_1[5]: - U[1,1] + Avg_TRCU[5] = 0
 avg_TRCU_1[6]: - U[1,1] + Avg_TRCU[6] = 0
 avg_TRCU_1[7]: - U[1,1] + Avg_TRCU[7] = 0
 avg_TRCU_1[8]: - U[1,1] + Avg_TRCU[8] = 0
 avg_TRCU_1[9]: - U[1,1] + Avg_TRCU[9] = 0
 avg_TRCU_1[10]: - U[1,1] + Avg_TRCU[10] = 0
 avg_TRCU_1[11]: - U[1,1] + Avg_TRCU[11] = 0
 avg_TRCU_1[12]: - U[1,1] + Avg_TRCU[12] = 0
 avg_TRCU_1[13]: - U[1,1] + Avg_TRCU[13] = 0
 avg_TRCU_1[14]: - U[1,1] + Avg_TRCU[14] = 0
 avg_TRCU_1[15]: - U[1,1] + Avg_TRCU[15] = 0
 avg_TRCU_1[16]: - U[1,1] + Avg_TRCU[16] = 0
 avg_TRCU_1[17]: - U[1,1] + Avg_TRCU[17] = 0
 avg_TRCU_1[18]: - U[1,1] + Avg_TRCU[18] = 0
 avg_TRCU_1[19]: - U[1,1] + Avg_TRCU[19] = 0
 avg_TRCU_1[20]: - U[1,1] + Avg_TRCU[20] = 0
 avg_TRCU_1[21]: - U[1,1] + Avg_TRCU[21] = 0
 avg_TRCU_1[22]: - U[1,1] + Avg_TRCU[22] = 0
 avg_TRCU_1[23]: - U[1,1] + Avg_TRCU[23] = 0
 cooling_power_1: - 0.2857142857142857 H_1[1] + P_source[1] = 0
 total_cooling_power_1: - P_source[1] - P_fan[1] + P_cooling[1] = 0
 PS1_2: U[2,1] - 1.333333333333333 L_BW[0,2] - 100.5 A_DC[1]
   = 186.6666666666667
 PS2_2: U[3,1] - 1.333333333333333 L_BW[1,2] - 100.5 A_DC[1]
   = 186.6666666666667
 temp_dynamics_X_1_2[0]: rack_1[0,2] - 8.2918739635157504e-04 U[0,1]
   - 0.9121061359867327 U[1,1] - 0.0071198776435842 U[2,1] = 0
 temp_dynamics_X_1_2[1]: rack_1[1,2] - 8.2918739635157504e-04 U[0,1]
   - 0.9121061359867327 U[1,1] - 0.0071198776435842 U[3,1] = 0
 temp_dynamics_X_1_2[2]: rack_1[2,2] - 8.2918739635157504e-04 U[0,1]
   - 0.9121061359867327 U[1,1] - 0.0188398408428998 U[2,1] = 0
 temp_dynamics_X_1_2[3]: rack_1[3,2] - 8.2918739635157504e-04 U[0,1]
   - 0.9121061359867327 U[1,1] - 0.0188398408428998 U[3,1] = 0
 avg_TRCU_2[0]: - U[1,2] + Avg_TRCU[0] = 0
 avg_TRCU_2[1]: - U[1,2] + Avg_TRCU[1] = 0
 avg_TRCU_2[2]: - U[1,2] + Avg_TRCU[2] = 0
 avg_TRCU_2[3]: - U[1,2] + Avg_TRCU[3] = 0
 avg_TRCU_2[4]: - U[1,2] + Avg_TRCU[4] = 0
 avg_TRCU_2[5]: - U[1,2] + Avg_TRCU[5] = 0
 avg_TRCU_2[6]: - U[1,2] + Avg_TRCU[6] = 0
 avg_TRCU_2[7]: - U[1,2] + Avg_TRCU[7] = 0
 avg_TRCU_2[8]: - U[1,2] + Avg_TRCU[8] = 0
 avg_TRCU_2[9]: - U[1,2] + Avg_TRCU[9] = 0
 avg_TRCU_2[10]: - U[1,2] + Avg_TRCU[10] = 0
 avg_TRCU_2[11]: - U[1,2] + Avg_TRCU[11] = 0
 avg_TRCU_2[12]: - U[1,2] + Avg_TRCU[12] = 0
 avg_TRCU_2[13]: - U[1,2] + Avg_TRCU[13] = 0
 avg_TRCU_2[14]: - U[1,2] + Avg_TRCU[14] = 0
 avg_TRCU_2[15]: - U[1,2] + Avg_TRCU[15] = 0
 avg_TRCU_2[16]: - U[1,2] + Avg_TRCU[16] = 0
 avg_TRCU_2[17]: - U[1,2] + Avg_TRCU[17] = 0
 avg_TRCU_2[18]: - U[1,2] + Avg_TRCU[18] = 0
 avg_TRCU_2[19]: - U[1,2] + Avg_TRCU[19] = 0
 avg_TRCU_2[20]: - U[1,2] + Avg_TRCU[20] = 0
 avg_TRCU_2[21]: - U[1,2] + Avg_TRCU[21] = 0
 avg_TRCU_2[22]: - U[1,2] + Avg_TRCU[22] = 0
 avg_TRCU_2[23]: - U[1,2] + Avg_TRCU[23] = 0
 cooling_power_2: - 0.2857142857142857 H_1[2] + P_source[2] = 0
 total_cooling_power_2: - P_source[2] - P_fan[2] + P_cooling[2] = 0
 PS1_3: U[2,2] - 1.333333333333333 L_BW[0,3] - 100.5 A_DC[2]
   = 173.3333333333333
 PS2_3: U[3,2] - 1.333333333333333 L_BW[1,3] - 100.5 A_DC[2]
   = 173.3333333333333
 temp_dynamics_X_1_3[0]: rack_1[0,3] - 8.2918739635157504e-04 U[0,2]
   - 0.9121061359867327 U[1,2] - 0.0071198776435842 U[2,2] = 0
 temp_dynamics_X_1_3[1]: rack_1[1,3] - 8.2918739635157504e-04 U[0,2]
   - 0.9121061359867327 U[1,2] - 0.0071198776435842 U[3,2] = 0
 temp_dynamics_X_1_3[2]: rack_1[2,3] - 8.2918739635157504e-04 U[0,2]
   - 0.9121061359867327 U[1,2] - 0.0188398408428998 U[2,2] = 0
 temp_dynamics_X_1_3[3]: rack_1[3,3] - 8.2918739635157504e-04 U[0,2]
   - 0.9121061359867327 U[1,2] - 0.0188398408428998 U[3,2] = 0
 avg_TRCU_3[0]: - U[1,3] + Avg_TRCU[0] = 0
 avg_TRCU_3[1]: - U[1,3] + Avg_TRCU[1] = 0
 avg_TRCU_3[2]: - U[1,3] + Avg_TRCU[2] = 0
 avg_TRCU_3[3]: - U[1,3] + Avg_TRCU[3] = 0
 avg_TRCU_3[4]: - U[1,3] + Avg_TRCU[4] = 0
 avg_TRCU_3[5]: - U[1,3] + Avg_TRCU[5] = 0
 avg_TRCU_3[6]: - U[1,3] + Avg_TRCU[6] = 0
 avg_TRCU_3[7]: - U[1,3] + Avg_TRCU[7] = 0
 avg_TRCU_3[8]: - U[1,3] + Avg_TRCU[8] = 0
 avg_TRCU_3[9]: - U[1,3] + Avg_TRCU[9] = 0
 avg_TRCU_3[10]: - U[1,3] + Avg_TRCU[10] = 0
 avg_TRCU_3[11]: - U[1,3] + Avg_TRCU[11] = 0
 avg_TRCU_3[12]: - U[1,3] + Avg_TRCU[12] = 0
 avg_TRCU_3[13]: - U[1,3] + Avg_TRCU[13] = 0
 avg_TRCU_3[14]: - U[1,3] + Avg_TRCU[14] = 0
 avg_TRCU_3[15]: - U[1,3] + Avg_TRCU[15] = 0
 avg_TRCU_3[16]: - U[1,3] + Avg_TRCU[16] = 0
 avg_TRCU_3[17]: - U[1,3] + Avg_TRCU[17] = 0
 avg_TRCU_3[18]: - U[1,3] + Avg_TRCU[18] = 0
 avg_TRCU_3[19]: - U[1,3] + Avg_TRCU[19] = 0
 avg_TRCU_3[20]: - U[1,3] + Avg_TRCU[20] = 0
 avg_TRCU_3[21]: - U[1,3] + Avg_TRCU[21] = 0
 avg_TRCU_3[22]: - U[1,3] + Avg_TRCU[22] = 0
 avg_TRCU_3[23]: - U[1,3] + Avg_TRCU[23] = 0
 cooling_power_3: - 0.2857142857142857 H_1[3] + P_source[3] = 0
 total_cooling_power_3: - P_source[3] - P_fan[3] + P_cooling[3] = 0
 PS1_4: U[2,3] - 1.333333333333333 L_BW[0,4] - 100.5 A_DC[3]
   = 166.6666666666667
 PS2_4: U[3,3] - 1.333333333333333 L_BW[1,4] - 100.5 A_DC[3]
   = 166.6666666666667
 temp_dynamics_X_1_4[0]: rack_1[0,4] - 8.2918739635157504e-04 U[0,3]
   - 0.9121061359867327 U[1,3] - 0.0071198776435842 U[2,3] = 0
 temp_dynamics_X_1_4[1]: rack_1[1,4] - 8.2918739635157504e-04 U[0,3]
   - 0.9121061359867327 U[1,3] - 0.0071198776435842 U[3,3] = 0
 temp_dynamics_X_1_4[2]: rack_1[2,4] - 8.2918739635157504e-04 U[0,3]
   - 0.9121061359867327 U[1,3] - 0.0188398408428998 U[2,3] = 0
 temp_dynamics_X_1_4[3]: rack_1[3,4] - 8.2918739635157504e-04 U[0,3]
   - 0.9121061359867327 U[1,3] - 0.0188398408428998 U[3,3] = 0
 avg_TRCU_4[0]: - U[1,4] + Avg_TRCU[0] = 0
 avg_TRCU_4[1]: - U[1,4] + Avg_TRCU[1] = 0
 avg_TRCU_4[2]: - U[1,4] + Avg_TRCU[2] = 0
 avg_TRCU_4[3]: - U[1,4] + Avg_TRCU[3] = 0
 avg_TRCU_4[4]: - U[1,4] + Avg_TRCU[4] = 0
 avg_TRCU_4[5]: - U[1,4] + Avg_TRCU[5] = 0
 avg_TRCU_4[6]: - U[1,4] + Avg_TRCU[6] = 0
 avg_TRCU_4[7]: - U[1,4] + Avg_TRCU[7] = 0
 avg_TRCU_4[8]: - U[1,4] + Avg_TRCU[8] = 0
 avg_TRCU_4[9]: - U[1,4] + Avg_TRCU[9] = 0
 avg_TRCU_4[10]: - U[1,4] + Avg_TRCU[10] = 0
 avg_TRCU_4[11]: - U[1,4] + Avg_TRCU[11] = 0
 avg_TRCU_4[12]: - U[1,4] + Avg_TRCU[12] = 0
 avg_TRCU_4[13]: - U[1,4] + Avg_TRCU[13] = 0
 avg_TRCU_4[14]: - U[1,4] + Avg_TRCU[14] = 0
 avg_TRCU_4[15]: - U[1,4] + Avg_TRCU[15] = 0
 avg_TRCU_4[16]: - U[1,4] + Avg_TRCU[16] = 0
 avg_TRCU_4[17]: - U[1,4] + Avg_TRCU[17] = 0
 avg_TRCU_4[18]: - U[1,4] + Avg_TRCU[18] = 0
 avg_TRCU_4[19]: - U[1,4] + Avg_TRCU[19] = 0
 avg_TRCU_4[20]: - U[1,4] + Avg_TRCU[20] = 0
 avg_TRCU_4[21]: - U[1,4] + Avg_TRCU[21] = 0
 avg_TRCU_4[22]: - U[1,4] + Avg_TRCU[22] = 0
 avg_TRCU_4[23]: - U[1,4] + Avg_TRCU[23] = 0
 cooling_power_4: - 0.2857142857142857 H_1[4] + P_source[4] = 0
 total_cooling_power_4: - P_source[4] - P_fan[4] + P_cooling[4] = 0
 PS1_5: U[2,4] - 1.333333333333333 L_BW[0,5] - 100.5 A_DC[4]
   = 173.3333333333333
 PS2_5: U[3,4] - 1.333333333333333 L_BW[1,5] - 100.5 A_DC[4]
   = 173.3333333333333
 temp_dynamics_X_1_5[0]: rack_1[0,5] - 8.2918739635157504e-04 U[0,4]
   - 0.9121061359867327 U[1,4] - 0.0071198776435842 U[2,4] = 0
 temp_dynamics_X_1_5[1]: rack_1[1,5] - 8.2918739635157504e-04 U[0,4]
   - 0.9121061359867327 U[1,4] - 0.0071198776435842 U[3,4] = 0
 temp_dynamics_X_1_5[2]: rack_1[2,5] - 8.2918739635157504e-04 U[0,4]
   - 0.9121061359867327 U[1,4] - 0.0188398408428998 U[2,4] = 0
 temp_dynamics_X_1_5[3]: rack_1[3,5] - 8.2918739635157504e-04 U[0,4]
   - 0.9121061359867327 U[1,4] - 0.0188398408428998 U[3,4] = 0
 avg_TRCU_5[0]: - U[1,5] + Avg_TRCU[0] = 0
 avg_TRCU_5[1]: - U[1,5] + Avg_TRCU[1] = 0
 avg_TRCU_5[2]: - U[1,5] + Avg_TRCU[2] = 0
 avg_TRCU_5[3]: - U[1,5] + Avg_TRCU[3] = 0
 avg_TRCU_5[4]: - U[1,5] + Avg_TRCU[4] = 0
 avg_TRCU_5[5]: - U[1,5] + Avg_TRCU[5] = 0
 avg_TRCU_5[6]: - U[1,5] + Avg_TRCU[6] = 0
 avg_TRCU_5[7]: - U[1,5] + Avg_TRCU[7] = 0
 avg_TRCU_5[8]: - U[1,5] + Avg_TRCU[8] = 0
 avg_TRCU_5[9]: - U[1,5] + Avg_TRCU[9] = 0
 avg_TRCU_5[10]: - U[1,5] + Avg_TRCU[10] = 0
 avg_TRCU_5[11]: - U[1,5] + Avg_TRCU[11] = 0
 avg_TRCU_5[12]: - U[1,5] + Avg_TRCU[12] = 0
 avg_TRCU_5[13]: - U[1,5] + Avg_TRCU[13] = 0
 avg_TRCU_5[14]: - U[1,5] + Avg_TRCU[14] = 0
 avg_TRCU_5[15]: - U[1,5] + Avg_TRCU[15] = 0
 avg_TRCU_5[16]: - U[1,5] + Avg_TRCU[16] = 0
 avg_TRCU_5[17]: - U[1,5] + Avg_TRCU[17] = 0
 avg_TRCU_5[18]: - U[1,5] + Avg_TRCU[18] = 0
 avg_TRCU_5[19]: - U[1,5] + Avg_TRCU[19] = 0
 avg_TRCU_5[20]: - U[1,5] + Avg_TRCU[20] = 0
 avg_TRCU_5[21]: - U[1,5] + Avg_TRCU[21] = 0
 avg_TRCU_5[22]: - U[1,5] + Avg_TRCU[22] = 0
 avg_TRCU_5[23]: - U[1,5] + Avg_TRCU[23] = 0
 cooling_power_5: - 0.2857142857142857 H_1[5] + P_source[5] = 0
 total_cooling_power_5: - P_source[5] - P_fan[5] + P_cooling[5] = 0
 PS1_6: U[2,5] - 1.333333333333333 L_BW[0,6] - 100.5 A_DC[5]
   = 233.3333333333333
 PS2_6: U[3,5] - 1.333333333333333 L_BW[1,6] - 100.5 A_DC[5]
   = 233.3333333333333
 temp_dynamics_X_1_6[0]: rack_1[0,6] - 8.2918739635157504e-04 U[0,5]
   - 0.9121061359867327 U[1,5] - 0.0071198776435842 U[2,5] = 0
 temp_dynamics_X_1_6[1]: rack_1[1,6] - 8.2918739635157504e-04 U[0,5]
   - 0.9121061359867327 U[1,5] - 0.0071198776435842 U[3,5] = 0
 temp_dynamics_X_1_6[2]: rack_1[2,6] - 8.2918739635157504e-04 U[0,5]
   - 0.9121061359867327 U[1,5] - 0.0188398408428998 U[2,5] = 0
 temp_dynamics_X_1_6[3]: rack_1[3,6] - 8.2918739635157504e-04 U[0,5]
   - 0.9121061359867327 U[1,5] - 0.0188398408428998 U[3,5] = 0
 avg_TRCU_6[0]: - U[1,6] + Avg_TRCU[0] = 0
 avg_TRCU_6[1]: - U[1,6] + Avg_TRCU[1] = 0
 avg_TRCU_6[2]: - U[1,6] + Avg_TRCU[2] = 0
 avg_TRCU_6[3]: - U[1,6] + Avg_TRCU[3] = 0
 avg_TRCU_6[4]: - U[1,6] + Avg_TRCU[4] = 0
 avg_TRCU_6[5]: - U[1,6] + Avg_TRCU[5] = 0
 avg_TRCU_6[6]: - U[1,6] + Avg_TRCU[6] = 0
 avg_TRCU_6[7]: - U[1,6] + Avg_TRCU[7] = 0
 avg_TRCU_6[8]: - U[1,6] + Avg_TRCU[8] = 0
 avg_TRCU_6[9]: - U[1,6] + Avg_TRCU[9] = 0
 avg_TRCU_6[10]: - U[1,6] + Avg_TRCU[10] = 0
 avg_TRCU_6[11]: - U[1,6] + Avg_TRCU[11] = 0
 avg_TRCU_6[12]: - U[1,6] + Avg_TRCU[12] = 0
 avg_TRCU_6[13]: - U[1,6] + Avg_TRCU[13] = 0
 avg_TRCU_6[14]: - U[1,6] + Avg_TRCU[14] = 0
 avg_TRCU_6[15]: - U[1,6] + Avg_TRCU[15] = 0
 avg_TRCU_6[16]: - U[1,6] + Avg_TRCU[16] = 0
 avg_TRCU_6[17]: - U[1,6] + Avg_TRCU[17] = 0
 avg_TRCU_6[18]: - U[1,6] + Avg_TRCU[18] = 0
 avg_TRCU_6[19]: - U[1,6] + Avg_TRCU[19] = 0
 avg_TRCU_6[20]: - U[1,6] + Avg_TRCU[20] = 0
 avg_TRCU_6[21]: - U[1,6] + Avg_TRCU[21] = 0
 avg_TRCU_6[22]: - U[1,6] + Avg_TRCU[22] = 0
 avg_TRCU_6[23]: - U[1,6] + Avg_TRCU[23] = 0
 cooling_power_6: - 0.2857142857142857 H_1[6] + P_source[6] = 0
 total_cooling_power_6: - P_source[6] - P_fan[6] + P_cooling[6] = 0
 PS1_7: U[2,6] - 1.333333333333333 L_BW[0,7] - 100.5 A_DC[6] = 400
 PS2_7: U[3,6] - 1.333333333333333 L_BW[1,7] - 100.5 A_DC[6] = 400
 temp_dynamics_X_1_7[0]: rack_1[0,7] - 8.2918739635157504e-04 U[0,6]
   - 0.9121061359867327 U[1,6] - 0.0071198776435842 U[2,6] = 0
 temp_dynamics_X_1_7[1]: rack_1[1,7] - 8.2918739635157504e-04 U[0,6]
   - 0.9121061359867327 U[1,6] - 0.0071198776435842 U[3,6] = 0
 temp_dynamics_X_1_7[2]: rack_1[2,7] - 8.2918739635157504e-04 U[0,6]
   - 0.9121061359867327 U[1,6] - 0.0188398408428998 U[2,6] = 0
 temp_dynamics_X_1_7[3]: rack_1[3,7] - 8.2918739635157504e-04 U[0,6]
   - 0.9121061359867327 U[1,6] - 0.0188398408428998 U[3,6] = 0
 avg_TRCU_7[0]: - U[1,7] + Avg_TRCU[0] = 0
 avg_TRCU_7[1]: - U[1,7] + Avg_TRCU[1] = 0
 avg_TRCU_7[2]: - U[1,7] + Avg_TRCU[2] = 0
 avg_TRCU_7[3]: - U[1,7] + Avg_TRCU[3] = 0
 avg_TRCU_7[4]: - U[1,7] + Avg_TRCU[4] = 0
 avg_TRCU_7[5]: - U[1,7] + Avg_TRCU[5] = 0
 avg_TRCU_7[6]: - U[1,7] + Avg_TRCU[6] = 0
 avg_TRCU_7[7]: - U[1,7] + Avg_TRCU[7] = 0
 avg_TRCU_7[8]: - U[1,7] + Avg_TRCU[8] = 0
 avg_TRCU_7[9]: - U[1,7] + Avg_TRCU[9] = 0
 avg_TRCU_7[10]: - U[1,7] + Avg_TRCU[10] = 0
 avg_TRCU_7[11]: - U[1,7] + Avg_TRCU[11] = 0
 avg_TRCU_7[12]: - U[1,7] + Avg_TRCU[12] = 0
 avg_TRCU_7[13]: - U[1,7] + Avg_TRCU[13] = 0
 avg_TRCU_7[14]: - U[1,7] + Avg_TRCU[14] = 0
 avg_TRCU_7[15]: - U[1,7] + Avg_TRCU[15] = 0
 avg_TRCU_7[16]: - U[1,7] + Avg_TRCU[16] = 0
 avg_TRCU_7[17]: - U[1,7] + Avg_TRCU[17] = 0
 avg_TRCU_7[18]: - U[1,7] + Avg_TRCU[18] = 0
 avg_TRCU_7[19]: - U[1,7] + Avg_TRCU[19] = 0
 avg_TRCU_7[20]: - U[1,7] + Avg_TRCU[20] = 0
 avg_TRCU_7[21]: - U[1,7] + Avg_TRCU[21] = 0
 avg_TRCU_7[22]: - U[1,7] + Avg_TRCU[22] = 0
 avg_TRCU_7[23]: - U[1,7] + Avg_TRCU[23] = 0
 cooling_power_7: - 0.2857142857142857 H_1[7] + P_source[7] = 0
 total_cooling_power_7: - P_source[7] - P_fan[7] + P_cooling[7] = 0
 PS1_8: U[2,7] - 1.333333333333333 L_BW[0,8] - 100.5 A_DC[7]
   = 533.3333333333335
 PS2_8: U[3,7] - 1.333333333333333 L_BW[1,8] - 100.5 A_DC[7]
   = 533.3333333333335
 temp_dynamics_X_1_8[0]: rack_1[0,8] - 8.2918739635157504e-04 U[0,7]
   - 0.9121061359867327 U[1,7] - 0.0071198776435842 U[2,7] = 0
 temp_dynamics_X_1_8[1]: rack_1[1,8] - 8.2918739635157504e-04 U[0,7]
   - 0.9121061359867327 U[1,7] - 0.0071198776435842 U[3,7] = 0
 temp_dynamics_X_1_8[2]: rack_1[2,8] - 8.2918739635157504e-04 U[0,7]
   - 0.9121061359867327 U[1,7] - 0.0188398408428998 U[2,7] = 0
 temp_dynamics_X_1_8[3]: rack_1[3,8] - 8.2918739635157504e-04 U[0,7]
   - 0.9121061359867327 U[1,7] - 0.0188398408428998 U[3,7] = 0
 avg_TRCU_8[0]: - U[1,8] + Avg_TRCU[0] = 0
 avg_TRCU_8[1]: - U[1,8] + Avg_TRCU[1] = 0
 avg_TRCU_8[2]: - U[1,8] + Avg_TRCU[2] = 0
 avg_TRCU_8[3]: - U[1,8] + Avg_TRCU[3] = 0
 avg_TRCU_8[4]: - U[1,8] + Avg_TRCU[4] = 0
 avg_TRCU_8[5]: - U[1,8] + Avg_TRCU[5] = 0
 avg_TRCU_8[6]: - U[1,8] + Avg_TRCU[6] = 0
 avg_TRCU_8[7]: - U[1,8] + Avg_TRCU[7] = 0
 avg_TRCU_8[8]: - U[1,8] + Avg_TRCU[8] = 0
 avg_TRCU_8[9]: - U[1,8] + Avg_TRCU[9] = 0
 avg_TRCU_8[10]: - U[1,8] + Avg_TRCU[10] = 0
 avg_TRCU_8[11]: - U[1,8] + Avg_TRCU[11] = 0
 avg_TRCU_8[12]: - U[1,8] + Avg_TRCU[12] = 0
 avg_TRCU_8[13]: - U[1,8] + Avg_TRCU[13] = 0
 avg_TRCU_8[14]: - U[1,8] + Avg_TRCU[14] = 0
 avg_TRCU_8[15]: - U[1,8] + Avg_TRCU[15] = 0
 avg_TRCU_8[16]: - U[1,8] + Avg_TRCU[16] = 0
 avg_TRCU_8[17]: - U[1,8] + Avg_TRCU[17] = 0
 avg_TRCU_8[18]: - U[1,8] + Avg_TRCU[18] = 0
 avg_TRCU_8[19]: - U[1,8] + Avg_TRCU[19] = 0
 avg_TRCU_8[20]: - U[1,8] + Avg_TRCU[20] = 0
 avg_TRCU_8[21]: - U[1,8] + Avg_TRCU[21] = 0
 avg_TRCU_8[22]: - U[1,8] + Avg_TRCU[22] = 0
 avg_TRCU_8[23]: - U[1,8] + Avg_TRCU[23] = 0
 cooling_power_8: - 0.2857142857142857 H_1[8] + P_source[8] = 0
 total_cooling_power_8: - P_source[8] - P_fan[8] + P_cooling[8] = 0
 PS1_9: U[2,8] - 1.333333333333333 L_BW[0,9] - 100.5 A_DC[8]
   = 666.6666666666667
 PS2_9: U[3,8] - 1.333333333333333 L_BW[1,9] - 100.5 A_DC[8]
   = 666.6666666666667
 temp_dynamics_X_1_9[0]: rack_1[0,9] - 8.2918739635157504e-04 U[0,8]
   - 0.9121061359867327 U[1,8] - 0.0071198776435842 U[2,8] = 0
 temp_dynamics_X_1_9[1]: rack_1[1,9] - 8.2918739635157504e-04 U[0,8]
   - 0.9121061359867327 U[1,8] - 0.0071198776435842 U[3,8] = 0
 temp_dynamics_X_1_9[2]: rack_1[2,9] - 8.2918739635157504e-04 U[0,8]
   - 0.9121061359867327 U[1,8] - 0.0188398408428998 U[2,8] = 0
 temp_dynamics_X_1_9[3]: rack_1[3,9] - 8.2918739635157504e-04 U[0,8]
   - 0.9121061359867327 U[1,8] - 0.0188398408428998 U[3,8] = 0
 avg_TRCU_9[0]: - U[1,9] + Avg_TRCU[0] = 0
 avg_TRCU_9[1]: - U[1,9] + Avg_TRCU[1] = 0
 avg_TRCU_9[2]: - U[1,9] + Avg_TRCU[2] = 0
 avg_TRCU_9[3]: - U[1,9] + Avg_TRCU[3] = 0
 avg_TRCU_9[4]: - U[1,9] + Avg_TRCU[4] = 0
 avg_TRCU_9[5]: - U[1,9] + Avg_TRCU[5] = 0
 avg_TRCU_9[6]: - U[1,9] + Avg_TRCU[6] = 0
 avg_TRCU_9[7]: - U[1,9] + Avg_TRCU[7] = 0
 avg_TRCU_9[8]: - U[1,9] + Avg_TRCU[8] = 0
 avg_TRCU_9[9]: - U[1,9] + Avg_TRCU[9] = 0
 avg_TRCU_9[10]: - U[1,9] + Avg_TRCU[10] = 0
 avg_TRCU_9[11]: - U[1,9] + Avg_TRCU[11] = 0
 avg_TRCU_9[12]: - U[1,9] + Avg_TRCU[12] = 0
 avg_TRCU_9[13]: - U[1,9] + Avg_TRCU[13] = 0
 avg_TRCU_9[14]: - U[1,9] + Avg_TRCU[14] = 0
 avg_TRCU_9[15]: - U[1,9] + Avg_TRCU[15] = 0
 avg_TRCU_9[16]: - U[1,9] + Avg_TRCU[16] = 0
 avg_TRCU_9[17]: - U[1,9] + Avg_TRCU[17] = 0
 avg_TRCU_9[18]: - U[1,9] + Avg_TRCU[18] = 0
 avg_TRCU_9[19]: - U[1,9] + Avg_TRCU[19] = 0
 avg_TRCU_9[20]: - U[1,9] + Avg_TRCU[20] = 0
 avg_TRCU_9[21]: - U[1,9] + Avg_TRCU[21] = 0
 avg_TRCU_9[22]: - U[1,9] + Avg_TRCU[22] = 0
 avg_TRCU_9[23]: - U[1,9] + Avg_TRCU[23] = 0
 cooling_power_9: - 0.2857142857142857 H_1[9] + P_source[9] = 0
 total_cooling_power_9: - P_source[9] - P_fan[9] + P_cooling[9] = 0
 PS1_10: U[2,9] - 1.333333333333333 L_BW[0,10] - 100.5 A_DC[9]
   = 733.3333333333334
 PS2_10: U[3,9] - 1.333333333333333 L_BW[1,10] - 100.5 A_DC[9]
   = 733.3333333333334
 temp_dynamics_X_1_10[0]: rack_1[0,10] - 8.2918739635157504e-04 U[0,9]
   - 0.9121061359867327 U[1,9] - 0.0071198776435842 U[2,9] = 0
 temp_dynamics_X_1_10[1]: rack_1[1,10] - 8.2918739635157504e-04 U[0,9]
   - 0.9121061359867327 U[1,9] - 0.0071198776435842 U[3,9] = 0
 temp_dynamics_X_1_10[2]: rack_1[2,10] - 8.2918739635157504e-04 U[0,9]
   - 0.9121061359867327 U[1,9] - 0.0188398408428998 U[2,9] = 0
 temp_dynamics_X_1_10[3]: rack_1[3,10] - 8.2918739635157504e-04 U[0,9]
   - 0.9121061359867327 U[1,9] - 0.0188398408428998 U[3,9] = 0
 avg_TRCU_10[0]: - U[1,10] + Avg_TRCU[0] = 0
 avg_TRCU_10[1]: - U[1,10] + Avg_TRCU[1] = 0
 avg_TRCU_10[2]: - U[1,10] + Avg_TRCU[2] = 0
 avg_TRCU_10[3]: - U[1,10] + Avg_TRCU[3] = 0
 avg_TRCU_10[4]: - U[1,10] + Avg_TRCU[4] = 0
 avg_TRCU_10[5]: - U[1,10] + Avg_TRCU[5] = 0
 avg_TRCU_10[6]: - U[1,10] + Avg_TRCU[6] = 0
 avg_TRCU_10[7]: - U[1,10] + Avg_TRCU[7] = 0
 avg_TRCU_10[8]: - U[1,10] + Avg_TRCU[8] = 0
 avg_TRCU_10[9]: - U[1,10] + Avg_TRCU[9] = 0
 avg_TRCU_10[10]: - U[1,10] + Avg_TRCU[10] = 0
 avg_TRCU_10[11]: - U[1,10] + Avg_TRCU[11] = 0
 avg_TRCU_10[12]: - U[1,10] + Avg_TRCU[12] = 0
 avg_TRCU_10[13]: - U[1,10] + Avg_TRCU[13] = 0
 avg_TRCU_10[14]: - U[1,10] + Avg_TRCU[14] = 0
 avg_TRCU_10[15]: - U[1,10] + Avg_TRCU[15] = 0
 avg_TRCU_10[16]: - U[1,10] + Avg_TRCU[16] = 0
 avg_TRCU_10[17]: - U[1,10] + Avg_TRCU[17] = 0
 avg_TRCU_10[18]: - U[1,10] + Avg_TRCU[18] = 0
 avg_TRCU_10[19]: - U[1,10] + Avg_TRCU[19] = 0
 avg_TRCU_10[20]: - U[1,10] + Avg_TRCU[20] = 0
 avg_TRCU_10[21]: - U[1,10] + Avg_TRCU[21] = 0
 avg_TRCU_10[22]: - U[1,10] + Avg_TRCU[22] = 0
 avg_TRCU_10[23]: - U[1,10] + Avg_TRCU[23] = 0
 cooling_power_10: - 0.2857142857142857 H_1[10] + P_source[10] = 0
 total_cooling_power_10: - P_source[10] - P_fan[10] + P_cooling[10] = 0
 PS1_11: U[2,10] - 1.333333333333333 L_BW[0,11] - 100.5 A_DC[10]
   = 766.6666666666667
 PS2_11: U[3,10] - 1.333333333333333 L_BW[1,11] - 100.5 A_DC[10]
   = 766.6666666666667
 temp_dynamics_X_1_11[0]: rack_1[0,11] - 8.2918739635157504e-04 U[0,10]
   - 0.9121061359867327 U[1,10] - 0.0071198776435842 U[2,10] = 0
 temp_dynamics_X_1_11[1]: rack_1[1,11] - 8.2918739635157504e-04 U[0,10]
   - 0.9121061359867327 U[1,10] - 0.0071198776435842 U[3,10] = 0
 temp_dynamics_X_1_11[2]: rack_1[2,11] - 8.2918739635157504e-04 U[0,10]
   - 0.9121061359867327 U[1,10] - 0.0188398408428998 U[2,10] = 0
 temp_dynamics_X_1_11[3]: rack_1[3,11] - 8.2918739635157504e-04 U[0,10]
   - 0.9121061359867327 U[1,10] - 0.0188398408428998 U[3,10] = 0
 avg_TRCU_11[0]: - U[1,11] + Avg_TRCU[0] = 0
 avg_TRCU_11[1]: - U[1,11] + Avg_TRCU[1] = 0
 avg_TRCU_11[2]: - U[1,11] + Avg_TRCU[2] = 0
 avg_TRCU_11[3]: - U[1,11] + Avg_TRCU[3] = 0
 avg_TRCU_11[4]: - U[1,11] + Avg_TRCU[4] = 0
 avg_TRCU_11[5]: - U[1,11] + Avg_TRCU[5] = 0
 avg_TRCU_11[6]: - U[1,11] + Avg_TRCU[6] = 0
 avg_TRCU_11[7]: - U[1,11] + Avg_TRCU[7] = 0
 avg_TRCU_11[8]: - U[1,11] + Avg_TRCU[8] = 0
 avg_TRCU_11[9]: - U[1,11] + Avg_TRCU[9] = 0
 avg_TRCU_11[10]: - U[1,11] + Avg_TRCU[10] = 0
 avg_TRCU_11[11]: - U[1,11] + Avg_TRCU[11] = 0
 avg_TRCU_11[12]: - U[1,11] + Avg_TRCU[12] = 0
 avg_TRCU_11[13]: - U[1,11] + Avg_TRCU[13] = 0
 avg_TRCU_11[14]: - U[1,11] + Avg_TRCU[14] = 0
 avg_TRCU_11[15]: - U[1,11] + Avg_TRCU[15] = 0
 avg_TRCU_11[16]: - U[1,11] + Avg_TRCU[16] = 0
 avg_TRCU_11[17]: - U[1,11] + Avg_TRCU[17] = 0
 avg_TRCU_11[18]: - U[1,11] + Avg_TRCU[18] = 0
 avg_TRCU_11[19]: - U[1,11] + Avg_TRCU[19] = 0
 avg_TRCU_11[20]: - U[1,11] + Avg_TRCU[20] = 0
 avg_TRCU_11[21]: - U[1,11] + Avg_TRCU[21] = 0
 avg_TRCU_11[22]: - U[1,11] + Avg_TRCU[22] = 0
 avg_TRCU_11[23]: - U[1,11] + Avg_TRCU[23] = 0
 cooling_power_11: - 0.2857142857142857 H_1[11] + P_source[11] = 0
 total_cooling_power_11: - P_source[11] - P_fan[11] + P_cooling[11] = 0
 PS1_12: U[2,11] - 1.333333333333333 L_BW[0,12] - 100.5 A_DC[11] = 800
 PS2_12: U[3,11] - 1.333333333333333 L_BW[1,12] - 100.5 A_DC[11] = 800
 temp_dynamics_X_1_12[0]: rack_1[0,12] - 8.2918739635157504e-04 U[0,11]
   - 0.9121061359867327 U[1,11] - 0.0071198776435842 U[2,11] = 0
 temp_dynamics_X_1_12[1]: rack_1[1,12] - 8.2918739635157504e-04 U[0,11]
   - 0.9121061359867327 U[1,11] - 0.0071198776435842 U[3,11] = 0
 temp_dynamics_X_1_12[2]: rack_1[2,12] - 8.2918739635157504e-04 U[0,11]
   - 0.9121061359867327 U[1,11] - 0.0188398408428998 U[2,11] = 0
 temp_dynamics_X_1_12[3]: rack_1[3,12] - 8.2918739635157504e-04 U[0,11]
   - 0.9121061359867327 U[1,11] - 0.0188398408428998 U[3,11] = 0
 avg_TRCU_12[0]: - U[1,12] + Avg_TRCU[0] = 0
 avg_TRCU_12[1]: - U[1,12] + Avg_TRCU[1] = 0
 avg_TRCU_12[2]: - U[1,12] + Avg_TRCU[2] = 0
 avg_TRCU_12[3]: - U[1,12] + Avg_TRCU[3] = 0
 avg_TRCU_12[4]: - U[1,12] + Avg_TRCU[4] = 0
 avg_TRCU_12[5]: - U[1,12] + Avg_TRCU[5] = 0
 avg_TRCU_12[6]: - U[1,12] + Avg_TRCU[6] = 0
 avg_TRCU_12[7]: - U[1,12] + Avg_TRCU[7] = 0
 avg_TRCU_12[8]: - U[1,12] + Avg_TRCU[8] = 0
 avg_TRCU_12[9]: - U[1,12] + Avg_TRCU[9] = 0
 avg_TRCU_12[10]: - U[1,12] + Avg_TRCU[10] = 0
 avg_TRCU_12[11]: - U[1,12] + Avg_TRCU[11] = 0
 avg_TRCU_12[12]: - U[1,12] + Avg_TRCU[12] = 0
 avg_TRCU_12[13]: - U[1,12] + Avg_TRCU[13] = 0
 avg_TRCU_12[14]: - U[1,12] + Avg_TRCU[14] = 0
 avg_TRCU_12[15]: - U[1,12] + Avg_TRCU[15] = 0
 avg_TRCU_12[16]: - U[1,12] + Avg_TRCU[16] = 0
 avg_TRCU_12[17]: - U[1,12] + Avg_TRCU[17] = 0
 avg_TRCU_12[18]: - U[1,12] + Avg_TRCU[18] = 0
 avg_TRCU_12[19]: - U[1,12] + Avg_TRCU[19] = 0
 avg_TRCU_12[20]: - U[1,12] + Avg_TRCU[20] = 0
 avg_TRCU_12[21]: - U[1,12] + Avg_TRCU[21] = 0
 avg_TRCU_12[22]: - U[1,12] + Avg_TRCU[22] = 0
 avg_TRCU_12[23]: - U[1,12] + Avg_TRCU[23] = 0
 cooling_power_12: - 0.2857142857142857 H_1[12] + P_source[12] = 0
 total_cooling_power_12: - P_source[12] - P_fan[12] + P_cooling[12] = 0
 PS1_13: U[2,12] - 1.333333333333333 L_BW[0,13] - 100.5 A_DC[12] = 800
 PS2_13: U[3,12] - 1.333333333333333 L_BW[1,13] - 100.5 A_DC[12] = 800
 temp_dynamics_X_1_13[0]: rack_1[0,13] - 8.2918739635157504e-04 U[0,12]
   - 0.9121061359867327 U[1,12] - 0.0071198776435842 U[2,12] = 0
 temp_dynamics_X_1_13[1]: rack_1[1,13] - 8.2918739635157504e-04 U[0,12]
   - 0.9121061359867327 U[1,12] - 0.0071198776435842 U[3,12] = 0
 temp_dynamics_X_1_13[2]: rack_1[2,13] - 8.2918739635157504e-04 U[0,12]
   - 0.9121061359867327 U[1,12] - 0.0188398408428998 U[2,12] = 0
 temp_dynamics_X_1_13[3]: rack_1[3,13] - 8.2918739635157504e-04 U[0,12]
   - 0.9121061359867327 U[1,12] - 0.0188398408428998 U[3,12] = 0
 avg_TRCU_13[0]: - U[1,13] + Avg_TRCU[0] = 0
 avg_TRCU_13[1]: - U[1,13] + Avg_TRCU[1] = 0
 avg_TRCU_13[2]: - U[1,13] + Avg_TRCU[2] = 0
 avg_TRCU_13[3]: - U[1,13] + Avg_TRCU[3] = 0
 avg_TRCU_13[4]: - U[1,13] + Avg_TRCU[4] = 0
 avg_TRCU_13[5]: - U[1,13] + Avg_TRCU[5] = 0
 avg_TRCU_13[6]: - U[1,13] + Avg_TRCU[6] = 0
 avg_TRCU_13[7]: - U[1,13] + Avg_TRCU[7] = 0
 avg_TRCU_13[8]: - U[1,13] + Avg_TRCU[8] = 0
 avg_TRCU_13[9]: - U[1,13] + Avg_TRCU[9] = 0
 avg_TRCU_13[10]: - U[1,13] + Avg_TRCU[10] = 0
 avg_TRCU_13[11]: - U[1,13] + Avg_TRCU[11] = 0
 avg_TRCU_13[12]: - U[1,13] + Avg_TRCU[12] = 0
 avg_TRCU_13[13]: - U[1,13] + Avg_TRCU[13] = 0
 avg_TRCU_13[14]: - U[1,13] + Avg_TRCU[14] = 0
 avg_TRCU_13[15]: - U[1,13] + Avg_TRCU[15] = 0
 avg_TRCU_13[16]: - U[1,13] + Avg_TRCU[16] = 0
 avg_TRCU_13[17]: - U[1,13] + Avg_TRCU[17] = 0
 avg_TRCU_13[18]: - U[1,13] + Avg_TRCU[18] = 0
 avg_TRCU_13[19]: - U[1,13] + Avg_TRCU[19] = 0
 avg_TRCU_13[20]: - U[1,13] + Avg_TRCU[20] = 0
 avg_TRCU_13[21]: - U[1,13] + Avg_TRCU[21] = 0
 avg_TRCU_13[22]: - U[1,13] + Avg_TRCU[22] = 0
 avg_TRCU_13[23]: - U[1,13] + Avg_TRCU[23] = 0
 cooling_power_13: - 0.2857142857142857 H_1[13] + P_source[13] = 0
 total_cooling_power_13: - P_source[13] - P_fan[13] + P_cooling[13] = 0
 PS1_14: U[2,13] - 1.333333333333333 L_BW[0,14] - 100.5 A_DC[13]
   = 766.6666666666667
 PS2_14: U[3,13] - 1.333333333333333 L_BW[1,14] - 100.5 A_DC[13]
   = 766.6666666666667
 temp_dynamics_X_1_14[0]: rack_1[0,14] - 8.2918739635157504e-04 U[0,13]
   - 0.9121061359867327 U[1,13] - 0.0071198776435842 U[2,13] = 0
 temp_dynamics_X_1_14[1]: rack_1[1,14] - 8.2918739635157504e-04 U[0,13]
   - 0.9121061359867327 U[1,13] - 0.0071198776435842 U[3,13] = 0
 temp_dynamics_X_1_14[2]: rack_1[2,14] - 8.2918739635157504e-04 U[0,13]
   - 0.9121061359867327 U[1,13] - 0.0188398408428998 U[2,13] = 0
 temp_dynamics_X_1_14[3]: rack_1[3,14] - 8.2918739635157504e-04 U[0,13]
   - 0.9121061359867327 U[1,13] - 0.0188398408428998 U[3,13] = 0
 avg_TRCU_14[0]: - U[1,14] + Avg_TRCU[0] = 0
 avg_TRCU_14[1]: - U[1,14] + Avg_TRCU[1] = 0
 avg_TRCU_14[2]: - U[1,14] + Avg_TRCU[2] = 0
 avg_TRCU_14[3]: - U[1,14] + Avg_TRCU[3] = 0
 avg_TRCU_14[4]: - U[1,14] + Avg_TRCU[4] = 0
 avg_TRCU_14[5]: - U[1,14] + Avg_TRCU[5] = 0
 avg_TRCU_14[6]: - U[1,14] + Avg_TRCU[6] = 0
 avg_TRCU_14[7]: - U[1,14] + Avg_TRCU[7] = 0
 avg_TRCU_14[8]: - U[1,14] + Avg_TRCU[8] = 0
 avg_TRCU_14[9]: - U[1,14] + Avg_TRCU[9] = 0
 avg_TRCU_14[10]: - U[1,14] + Avg_TRCU[10] = 0
 avg_TRCU_14[11]: - U[1,14] + Avg_TRCU[11] = 0
 avg_TRCU_14[12]: - U[1,14] + Avg_TRCU[12] = 0
 avg_TRCU_14[13]: - U[1,14] + Avg_TRCU[13] = 0
 avg_TRCU_14[14]: - U[1,14] + Avg_TRCU[14] = 0
 avg_TRCU_14[15]: - U[1,14] + Avg_TRCU[15] = 0
 avg_TRCU_14[16]: - U[1,14] + Avg_TRCU[16] = 0
 avg_TRCU_14[17]: - U[1,14] + Avg_TRCU[17] = 0
 avg_TRCU_14[18]: - U[1,14] + Avg_TRCU[18] = 0
 avg_TRCU_14[19]: - U[1,14] + Avg_TRCU[19] = 0
 avg_TRCU_14[20]: - U[1,14] + Avg_TRCU[20] = 0
 avg_TRCU_14[21]: - U[1,14] + Avg_TRCU[21] = 0
 avg_TRCU_14[22]: - U[1,14] + Avg_TRCU[22] = 0
 avg_TRCU_14[23]: - U[1,14] + Avg_TRCU[23] = 0
 cooling_power_14: - 0.2857142857142857 H_1[14] + P_source[14] = 0
 total_cooling_power_14: - P_source[14] - P_fan[14] + P_cooling[14] = 0
 PS1_15: U[2,14] - 1.333333333333333 L_BW[0,15] - 100.5 A_DC[14]
   = 733.3333333333334
 PS2_15: U[3,14] - 1.333333333333333 L_BW[1,15] - 100.5 A_DC[14]
   = 733.3333333333334
 temp_dynamics_X_1_15[0]: rack_1[0,15] - 8.2918739635157504e-04 U[0,14]
   - 0.9121061359867327 U[1,14] - 0.0071198776435842 U[2,14] = 0
 temp_dynamics_X_1_15[1]: rack_1[1,15] - 8.2918739635157504e-04 U[0,14]
   - 0.9121061359867327 U[1,14] - 0.0071198776435842 U[3,14] = 0
 temp_dynamics_X_1_15[2]: rack_1[2,15] - 8.2918739635157504e-04 U[0,14]
   - 0.9121061359867327 U[1,14] - 0.0188398408428998 U[2,14] = 0
 temp_dynamics_X_1_15[3]: rack_1[3,15] - 8.2918739635157504e-04 U[0,14]
   - 0.9121061359867327 U[1,14] - 0.0188398408428998 U[3,14] = 0
 avg_TRCU_15[0]: - U[1,15] + Avg_TRCU[0] = 0
 avg_TRCU_15[1]: - U[1,15] + Avg_TRCU[1] = 0
 avg_TRCU_15[2]: - U[1,15] + Avg_TRCU[2] = 0
 avg_TRCU_15[3]: - U[1,15] + Avg_TRCU[3] = 0
 avg_TRCU_15[4]: - U[1,15] + Avg_TRCU[4] = 0
 avg_TRCU_15[5]: - U[1,15] + Avg_TRCU[5] = 0
 avg_TRCU_15[6]: - U[1,15] + Avg_TRCU[6] = 0
 avg_TRCU_15[7]: - U[1,15] + Avg_TRCU[7] = 0
 avg_TRCU_15[8]: - U[1,15] + Avg_TRCU[8] = 0
 avg_TRCU_15[9]: - U[1,15] + Avg_TRCU[9] = 0
 avg_TRCU_15[10]: - U[1,15] + Avg_TRCU[10] = 0
 avg_TRCU_15[11]: - U[1,15] + Avg_TRCU[11] = 0
 avg_TRCU_15[12]: - U[1,15] + Avg_TRCU[12] = 0
 avg_TRCU_15[13]: - U[1,15] + Avg_TRCU[13] = 0
 avg_TRCU_15[14]: - U[1,15] + Avg_TRCU[14] = 0
 avg_TRCU_15[15]: - U[1,15] + Avg_TRCU[15] = 0
 avg_TRCU_15[16]: - U[1,15] + Avg_TRCU[16] = 0
 avg_TRCU_15[17]: - U[1,15] + Avg_TRCU[17] = 0
 avg_TRCU_15[18]: - U[1,15] + Avg_TRCU[18] = 0
 avg_TRCU_15[19]: - U[1,15] + Avg_TRCU[19] = 0
 avg_TRCU_15[20]: - U[1,15] + Avg_TRCU[20] = 0
 avg_TRCU_15[21]: - U[1,15] + Avg_TRCU[21] = 0
 avg_TRCU_15[22]: - U[1,15] + Avg_TRCU[22] = 0
 avg_TRCU_15[23]: - U[1,15] + Avg_TRCU[23] = 0
 cooling_power_15: - 0.2857142857142857 H_1[15] + P_source[15] = 0
 total_cooling_power_15: - P_source[15] - P_fan[15] + P_cooling[15] = 0
 PS1_16: U[2,15] - 1.333333333333333 L_BW[0,16] - 100.5 A_DC[15]
   = 666.6666666666667
 PS2_16: U[3,15] - 1.333333333333333 L_BW[1,16] - 100.5 A_DC[15]
   = 666.6666666666667
 temp_dynamics_X_1_16[0]: rack_1[0,16] - 8.2918739635157504e-04 U[0,15]
   - 0.9121061359867327 U[1,15] - 0.0071198776435842 U[2,15] = 0
 temp_dynamics_X_1_16[1]: rack_1[1,16] - 8.2918739635157504e-04 U[0,15]
   - 0.9121061359867327 U[1,15] - 0.0071198776435842 U[3,15] = 0
 temp_dynamics_X_1_16[2]: rack_1[2,16] - 8.2918739635157504e-04 U[0,15]
   - 0.9121061359867327 U[1,15] - 0.0188398408428998 U[2,15] = 0
 temp_dynamics_X_1_16[3]: rack_1[3,16] - 8.2918739635157504e-04 U[0,15]
   - 0.9121061359867327 U[1,15] - 0.0188398408428998 U[3,15] = 0
 avg_TRCU_16[0]: - U[1,16] + Avg_TRCU[0] = 0
 avg_TRCU_16[1]: - U[1,16] + Avg_TRCU[1] = 0
 avg_TRCU_16[2]: - U[1,16] + Avg_TRCU[2] = 0
 avg_TRCU_16[3]: - U[1,16] + Avg_TRCU[3] = 0
 avg_TRCU_16[4]: - U[1,16] + Avg_TRCU[4] = 0
 avg_TRCU_16[5]: - U[1,16] + Avg_TRCU[5] = 0
 avg_TRCU_16[6]: - U[1,16] + Avg_TRCU[6] = 0
 avg_TRCU_16[7]: - U[1,16] + Avg_TRCU[7] = 0
 avg_TRCU_16[8]: - U[1,16] + Avg_TRCU[8] = 0
 avg_TRCU_16[9]: - U[1,16] + Avg_TRCU[9] = 0
 avg_TRCU_16[10]: - U[1,16] + Avg_TRCU[10] = 0
 avg_TRCU_16[11]: - U[1,16] + Avg_TRCU[11] = 0
 avg_TRCU_16[12]: - U[1,16] + Avg_TRCU[12] = 0
 avg_TRCU_16[13]: - U[1,16] + Avg_TRCU[13] = 0
 avg_TRCU_16[14]: - U[1,16] + Avg_TRCU[14] = 0
 avg_TRCU_16[15]: - U[1,16] + Avg_TRCU[15] = 0
 avg_TRCU_16[16]: - U[1,16] + Avg_TRCU[16] = 0
 avg_TRCU_16[17]: - U[1,16] + Avg_TRCU[17] = 0
 avg_TRCU_16[18]: - U[1,16] + Avg_TRCU[18] = 0
 avg_TRCU_16[19]: - U[1,16] + Avg_TRCU[19] = 0
 avg_TRCU_16[20]: - U[1,16] + Avg_TRCU[20] = 0
 avg_TRCU_16[21]: - U[1,16] + Avg_TRCU[21] = 0
 avg_TRCU_16[22]: - U[1,16] + Avg_TRCU[22] = 0
 avg_TRCU_16[23]: - U[1,16] + Avg_TRCU[23] = 0
 cooling_power_16: - 0.2857142857142857 H_1[16] + P_source[16] = 0
 total_cooling_power_16: - P_source[16] - P_fan[16] + P_cooling[16] = 0
 PS1_17: U[2,16] - 1.333333333333333 L_BW[0,17] - 100.5 A_DC[16] = 600
 PS2_17: U[3,16] - 1.333333333333333 L_BW[1,17] - 100.5 A_DC[16] = 600
 temp_dynamics_X_1_17[0]: rack_1[0,17] - 8.2918739635157504e-04 U[0,16]
   - 0.9121061359867327 U[1,16] - 0.0071198776435842 U[2,16] = 0
 temp_dynamics_X_1_17[1]: rack_1[1,17] - 8.2918739635157504e-04 U[0,16]
   - 0.9121061359867327 U[1,16] - 0.0071198776435842 U[3,16] = 0
 temp_dynamics_X_1_17[2]: rack_1[2,17] - 8.2918739635157504e-04 U[0,16]
   - 0.9121061359867327 U[1,16] - 0.0188398408428998 U[2,16] = 0
 temp_dynamics_X_1_17[3]: rack_1[3,17] - 8.2918739635157504e-04 U[0,16]
   - 0.9121061359867327 U[1,16] - 0.0188398408428998 U[3,16] = 0
 avg_TRCU_17[0]: - U[1,17] + Avg_TRCU[0] = 0
 avg_TRCU_17[1]: - U[1,17] + Avg_TRCU[1] = 0
 avg_TRCU_17[2]: - U[1,17] + Avg_TRCU[2] = 0
 avg_TRCU_17[3]: - U[1,17] + Avg_TRCU[3] = 0
 avg_TRCU_17[4]: - U[1,17] + Avg_TRCU[4] = 0
 avg_TRCU_17[5]: - U[1,17] + Avg_TRCU[5] = 0
 avg_TRCU_17[6]: - U[1,17] + Avg_TRCU[6] = 0
 avg_TRCU_17[7]: - U[1,17] + Avg_TRCU[7] = 0
 avg_TRCU_17[8]: - U[1,17] + Avg_TRCU[8] = 0
 avg_TRCU_17[9]: - U[1,17] + Avg_TRCU[9] = 0
 avg_TRCU_17[10]: - U[1,17] + Avg_TRCU[10] = 0
 avg_TRCU_17[11]: - U[1,17] + Avg_TRCU[11] = 0
 avg_TRCU_17[12]: - U[1,17] + Avg_TRCU[12] = 0
 avg_TRCU_17[13]: - U[1,17] + Avg_TRCU[13] = 0
 avg_TRCU_17[14]: - U[1,17] + Avg_TRCU[14] = 0
 avg_TRCU_17[15]: - U[1,17] + Avg_TRCU[15] = 0
 avg_TRCU_17[16]: - U[1,17] + Avg_TRCU[16] = 0
 avg_TRCU_17[17]: - U[1,17] + Avg_TRCU[17] = 0
 avg_TRCU_17[18]: - U[1,17] + Avg_TRCU[18] = 0
 avg_TRCU_17[19]: - U[1,17] + Avg_TRCU[19] = 0
 avg_TRCU_17[20]: - U[1,17] + Avg_TRCU[20] = 0
 avg_TRCU_17[21]: - U[1,17] + Avg_TRCU[21] = 0
 avg_TRCU_17[22]: - U[1,17] + Avg_TRCU[22] = 0
 avg_TRCU_17[23]: - U[1,17] + Avg_TRCU[23] = 0
 cooling_power_17: - 0.2857142857142857 H_1[17] + P_source[17] = 0
 total_cooling_power_17: - P_source[17] - P_fan[17] + P_cooling[17] = 0
 PS1_18: U[2,17] - 1.333333333333333 L_BW[0,18] - 100.5 A_DC[17]
   = 533.3333333333335
 PS2_18: U[3,17] - 1.333333333333333 L_BW[1,18] - 100.5 A_DC[17]
   = 533.3333333333335
 temp_dynamics_X_1_18[0]: rack_1[0,18] - 8.2918739635157504e-04 U[0,17]
   - 0.9121061359867327 U[1,17] - 0.0071198776435842 U[2,17] = 0
 temp_dynamics_X_1_18[1]: rack_1[1,18] - 8.2918739635157504e-04 U[0,17]
   - 0.9121061359867327 U[1,17] - 0.0071198776435842 U[3,17] = 0
 temp_dynamics_X_1_18[2]: rack_1[2,18] - 8.2918739635157504e-04 U[0,17]
   - 0.9121061359867327 U[1,17] - 0.0188398408428998 U[2,17] = 0
 temp_dynamics_X_1_18[3]: rack_1[3,18] - 8.2918739635157504e-04 U[0,17]
   - 0.9121061359867327 U[1,17] - 0.0188398408428998 U[3,17] = 0
 avg_TRCU_18[0]: - U[1,18] + Avg_TRCU[0] = 0
 avg_TRCU_18[1]: - U[1,18] + Avg_TRCU[1] = 0
 avg_TRCU_18[2]: - U[1,18] + Avg_TRCU[2] = 0
 avg_TRCU_18[3]: - U[1,18] + Avg_TRCU[3] = 0
 avg_TRCU_18[4]: - U[1,18] + Avg_TRCU[4] = 0
 avg_TRCU_18[5]: - U[1,18] + Avg_TRCU[5] = 0
 avg_TRCU_18[6]: - U[1,18] + Avg_TRCU[6] = 0
 avg_TRCU_18[7]: - U[1,18] + Avg_TRCU[7] = 0
 avg_TRCU_18[8]: - U[1,18] + Avg_TRCU[8] = 0
 avg_TRCU_18[9]: - U[1,18] + Avg_TRCU[9] = 0
 avg_TRCU_18[10]: - U[1,18] + Avg_TRCU[10] = 0
 avg_TRCU_18[11]: - U[1,18] + Avg_TRCU[11] = 0
 avg_TRCU_18[12]: - U[1,18] + Avg_TRCU[12] = 0
 avg_TRCU_18[13]: - U[1,18] + Avg_TRCU[13] = 0
 avg_TRCU_18[14]: - U[1,18] + Avg_TRCU[14] = 0
 avg_TRCU_18[15]: - U[1,18] + Avg_TRCU[15] = 0
 avg_TRCU_18[16]: - U[1,18] + Avg_TRCU[16] = 0
 avg_TRCU_18[17]: - U[1,18] + Avg_TRCU[17] = 0
 avg_TRCU_18[18]: - U[1,18] + Avg_TRCU[18] = 0
 avg_TRCU_18[19]: - U[1,18] + Avg_TRCU[19] = 0
 avg_TRCU_18[20]: - U[1,18] + Avg_TRCU[20] = 0
 avg_TRCU_18[21]: - U[1,18] + Avg_TRCU[21] = 0
 avg_TRCU_18[22]: - U[1,18] + Avg_TRCU[22] = 0
 avg_TRCU_18[23]: - U[1,18] + Avg_TRCU[23] = 0
 cooling_power_18: - 0.2857142857142857 H_1[18] + P_source[18] = 0
 total_cooling_power_18: - P_source[18] - P_fan[18] + P_cooling[18] = 0
 PS1_19: U[2,18] - 1.333333333333333 L_BW[0,19] - 100.5 A_DC[18]
   = 466.6666666666667
 PS2_19: U[3,18] - 1.333333333333333 L_BW[1,19] - 100.5 A_DC[18]
   = 466.6666666666667
 temp_dynamics_X_1_19[0]: rack_1[0,19] - 8.2918739635157504e-04 U[0,18]
   - 0.9121061359867327 U[1,18] - 0.0071198776435842 U[2,18] = 0
 temp_dynamics_X_1_19[1]: rack_1[1,19] - 8.2918739635157504e-04 U[0,18]
   - 0.9121061359867327 U[1,18] - 0.0071198776435842 U[3,18] = 0
 temp_dynamics_X_1_19[2]: rack_1[2,19] - 8.2918739635157504e-04 U[0,18]
   - 0.9121061359867327 U[1,18] - 0.0188398408428998 U[2,18] = 0
 temp_dynamics_X_1_19[3]: rack_1[3,19] - 8.2918739635157504e-04 U[0,18]
   - 0.9121061359867327 U[1,18] - 0.0188398408428998 U[3,18] = 0
 avg_TRCU_19[0]: - U[1,19] + Avg_TRCU[0] = 0
 avg_TRCU_19[1]: - U[1,19] + Avg_TRCU[1] = 0
 avg_TRCU_19[2]: - U[1,19] + Avg_TRCU[2] = 0
 avg_TRCU_19[3]: - U[1,19] + Avg_TRCU[3] = 0
 avg_TRCU_19[4]: - U[1,19] + Avg_TRCU[4] = 0
 avg_TRCU_19[5]: - U[1,19] + Avg_TRCU[5] = 0
 avg_TRCU_19[6]: - U[1,19] + Avg_TRCU[6] = 0
 avg_TRCU_19[7]: - U[1,19] + Avg_TRCU[7] = 0
 avg_TRCU_19[8]: - U[1,19] + Avg_TRCU[8] = 0
 avg_TRCU_19[9]: - U[1,19] + Avg_TRCU[9] = 0
 avg_TRCU_19[10]: - U[1,19] + Avg_TRCU[10] = 0
 avg_TRCU_19[11]: - U[1,19] + Avg_TRCU[11] = 0
 avg_TRCU_19[12]: - U[1,19] + Avg_TRCU[12] = 0
 avg_TRCU_19[13]: - U[1,19] + Avg_TRCU[13] = 0
 avg_TRCU_19[14]: - U[1,19] + Avg_TRCU[14] = 0
 avg_TRCU_19[15]: - U[1,19] + Avg_TRCU[15] = 0
 avg_TRCU_19[16]: - U[1,19] + Avg_TRCU[16] = 0
 avg_TRCU_19[17]: - U[1,19] + Avg_TRCU[17] = 0
 avg_TRCU_19[18]: - U[1,19] + Avg_TRCU[18] = 0
 avg_TRCU_19[19]: - U[1,19] + Avg_TRCU[19] = 0
 avg_TRCU_19[20]: - U[1,19] + Avg_TRCU[20] = 0
 avg_TRCU_19[21]: - U[1,19] + Avg_TRCU[21] = 0
 avg_TRCU_19[22]: - U[1,19] + Avg_TRCU[22] = 0
 avg_TRCU_19[23]: - U[1,19] + Avg_TRCU[23] = 0
 cooling_power_19: - 0.2857142857142857 H_1[19] + P_source[19] = 0
 total_cooling_power_19: - P_source[19] - P_fan[19] + P_cooling[19] = 0
 PS1_20: U[2,19] - 1.333333333333333 L_BW[0,20] - 100.5 A_DC[19] = 400
 PS2_20: U[3,19] - 1.333333333333333 L_BW[1,20] - 100.5 A_DC[19] = 400
 temp_dynamics_X_1_20[0]: rack_1[0,20] - 8.2918739635157504e-04 U[0,19]
   - 0.9121061359867327 U[1,19] - 0.0071198776435842 U[2,19] = 0
 temp_dynamics_X_1_20[1]: rack_1[1,20] - 8.2918739635157504e-04 U[0,19]
   - 0.9121061359867327 U[1,19] - 0.0071198776435842 U[3,19] = 0
 temp_dynamics_X_1_20[2]: rack_1[2,20] - 8.2918739635157504e-04 U[0,19]
   - 0.9121061359867327 U[1,19] - 0.0188398408428998 U[2,19] = 0
 temp_dynamics_X_1_20[3]: rack_1[3,20] - 8.2918739635157504e-04 U[0,19]
   - 0.9121061359867327 U[1,19] - 0.0188398408428998 U[3,19] = 0
 avg_TRCU_20[0]: - U[1,20] + Avg_TRCU[0] = 0
 avg_TRCU_20[1]: - U[1,20] + Avg_TRCU[1] = 0
 avg_TRCU_20[2]: - U[1,20] + Avg_TRCU[2] = 0
 avg_TRCU_20[3]: - U[1,20] + Avg_TRCU[3] = 0
 avg_TRCU_20[4]: - U[1,20] + Avg_TRCU[4] = 0
 avg_TRCU_20[5]: - U[1,20] + Avg_TRCU[5] = 0
 avg_TRCU_20[6]: - U[1,20] + Avg_TRCU[6] = 0
 avg_TRCU_20[7]: - U[1,20] + Avg_TRCU[7] = 0
 avg_TRCU_20[8]: - U[1,20] + Avg_TRCU[8] = 0
 avg_TRCU_20[9]: - U[1,20] + Avg_TRCU[9] = 0
 avg_TRCU_20[10]: - U[1,20] + Avg_TRCU[10] = 0
 avg_TRCU_20[11]: - U[1,20] + Avg_TRCU[11] = 0
 avg_TRCU_20[12]: - U[1,20] + Avg_TRCU[12] = 0
 avg_TRCU_20[13]: - U[1,20] + Avg_TRCU[13] = 0
 avg_TRCU_20[14]: - U[1,20] + Avg_TRCU[14] = 0
 avg_TRCU_20[15]: - U[1,20] + Avg_TRCU[15] = 0
 avg_TRCU_20[16]: - U[1,20] + Avg_TRCU[16] = 0
 avg_TRCU_20[17]: - U[1,20] + Avg_TRCU[17] = 0
 avg_TRCU_20[18]: - U[1,20] + Avg_TRCU[18] = 0
 avg_TRCU_20[19]: - U[1,20] + Avg_TRCU[19] = 0
 avg_TRCU_20[20]: - U[1,20] + Avg_TRCU[20] = 0
 avg_TRCU_20[21]: - U[1,20] + Avg_TRCU[21] = 0
 avg_TRCU_20[22]: - U[1,20] + Avg_TRCU[22] = 0
 avg_TRCU_20[23]: - U[1,20] + Avg_TRCU[23] = 0
 cooling_power_20: - 0.2857142857142857 H_1[20] + P_source[20] = 0
 total_cooling_power_20: - P_source[20] - P_fan[20] + P_cooling[20] = 0
 PS1_21: U[2,20] - 1.333333333333333 L_BW[0,21] - 100.5 A_DC[20]
   = 333.3333333333334
 PS2_21: U[3,20] - 1.333333333333333 L_BW[1,21] - 100.5 A_DC[20]
   = 333.3333333333334
 temp_dynamics_X_1_21[0]: rack_1[0,21] - 8.2918739635157504e-04 U[0,20]
   - 0.9121061359867327 U[1,20] - 0.0071198776435842 U[2,20] = 0
 temp_dynamics_X_1_21[1]: rack_1[1,21] - 8.2918739635157504e-04 U[0,20]
   - 0.9121061359867327 U[1,20] - 0.0071198776435842 U[3,20] = 0
 temp_dynamics_X_1_21[2]: rack_1[2,21] - 8.2918739635157504e-04 U[0,20]
   - 0.9121061359867327 U[1,20] - 0.0188398408428998 U[2,20] = 0
 temp_dynamics_X_1_21[3]: rack_1[3,21] - 8.2918739635157504e-04 U[0,20]
   - 0.9121061359867327 U[1,20] - 0.0188398408428998 U[3,20] = 0
 avg_TRCU_21[0]: - U[1,21] + Avg_TRCU[0] = 0
 avg_TRCU_21[1]: - U[1,21] + Avg_TRCU[1] = 0
 avg_TRCU_21[2]: - U[1,21] + Avg_TRCU[2] = 0
 avg_TRCU_21[3]: - U[1,21] + Avg_TRCU[3] = 0
 avg_TRCU_21[4]: - U[1,21] + Avg_TRCU[4] = 0
 avg_TRCU_21[5]: - U[1,21] + Avg_TRCU[5] = 0
 avg_TRCU_21[6]: - U[1,21] + Avg_TRCU[6] = 0
 avg_TRCU_21[7]: - U[1,21] + Avg_TRCU[7] = 0
 avg_TRCU_21[8]: - U[1,21] + Avg_TRCU[8] = 0
 avg_TRCU_21[9]: - U[1,21] + Avg_TRCU[9] = 0
 avg_TRCU_21[10]: - U[1,21] + Avg_TRCU[10] = 0
 avg_TRCU_21[11]: - U[1,21] + Avg_TRCU[11] = 0
 avg_TRCU_21[12]: - U[1,21] + Avg_TRCU[12] = 0
 avg_TRCU_21[13]: - U[1,21] + Avg_TRCU[13] = 0
 avg_TRCU_21[14]: - U[1,21] + Avg_TRCU[14] = 0
 avg_TRCU_21[15]: - U[1,21] + Avg_TRCU[15] = 0
 avg_TRCU_21[16]: - U[1,21] + Avg_TRCU[16] = 0
 avg_TRCU_21[17]: - U[1,21] + Avg_TRCU[17] = 0
 avg_TRCU_21[18]: - U[1,21] + Avg_TRCU[18] = 0
 avg_TRCU_21[19]: - U[1,21] + Avg_TRCU[19] = 0
 avg_TRCU_21[20]: - U[1,21] + Avg_TRCU[20] = 0
 avg_TRCU_21[21]: - U[1,21] + Avg_TRCU[21] = 0
 avg_TRCU_21[22]: - U[1,21] + Avg_TRCU[22] = 0
 avg_TRCU_21[23]: - U[1,21] + Avg_TRCU[23] = 0
 cooling_power_21: - 0.2857142857142857 H_1[21] + P_source[21] = 0
 total_cooling_power_21: - P_source[21] - P_fan[21] + P_cooling[21] = 0
 PS1_22: U[2,21] - 1.333333333333333 L_BW[0,22] - 100.5 A_DC[21]
   = 266.6666666666667
 PS2_22: U[3,21] - 1.333333333333333 L_BW[1,22] - 100.5 A_DC[21]
   = 266.6666666666667
 temp_dynamics_X_1_22[0]: rack_1[0,22] - 8.2918739635157504e-04 U[0,21]
   - 0.9121061359867327 U[1,21] - 0.0071198776435842 U[2,21] = 0
 temp_dynamics_X_1_22[1]: rack_1[1,22] - 8.2918739635157504e-04 U[0,21]
   - 0.9121061359867327 U[1,21] - 0.0071198776435842 U[3,21] = 0
 temp_dynamics_X_1_22[2]: rack_1[2,22] - 8.2918739635157504e-04 U[0,21]
   - 0.9121061359867327 U[1,21] - 0.0188398408428998 U[2,21] = 0
 temp_dynamics_X_1_22[3]: rack_1[3,22] - 8.2918739635157504e-04 U[0,21]
   - 0.9121061359867327 U[1,21] - 0.0188398408428998 U[3,21] = 0
 avg_TRCU_22[0]: - U[1,22] + Avg_TRCU[0] = 0
 avg_TRCU_22[1]: - U[1,22] + Avg_TRCU[1] = 0
 avg_TRCU_22[2]: - U[1,22] + Avg_TRCU[2] = 0
 avg_TRCU_22[3]: - U[1,22] + Avg_TRCU[3] = 0
 avg_TRCU_22[4]: - U[1,22] + Avg_TRCU[4] = 0
 avg_TRCU_22[5]: - U[1,22] + Avg_TRCU[5] = 0
 avg_TRCU_22[6]: - U[1,22] + Avg_TRCU[6] = 0
 avg_TRCU_22[7]: - U[1,22] + Avg_TRCU[7] = 0
 avg_TRCU_22[8]: - U[1,22] + Avg_TRCU[8] = 0
 avg_TRCU_22[9]: - U[1,22] + Avg_TRCU[9] = 0
 avg_TRCU_22[10]: - U[1,22] + Avg_TRCU[10] = 0
 avg_TRCU_22[11]: - U[1,22] + Avg_TRCU[11] = 0
 avg_TRCU_22[12]: - U[1,22] + Avg_TRCU[12] = 0
 avg_TRCU_22[13]: - U[1,22] + Avg_TRCU[13] = 0
 avg_TRCU_22[14]: - U[1,22] + Avg_TRCU[14] = 0
 avg_TRCU_22[15]: - U[1,22] + Avg_TRCU[15] = 0
 avg_TRCU_22[16]: - U[1,22] + Avg_TRCU[16] = 0
 avg_TRCU_22[17]: - U[1,22] + Avg_TRCU[17] = 0
 avg_TRCU_22[18]: - U[1,22] + Avg_TRCU[18] = 0
 avg_TRCU_22[19]: - U[1,22] + Avg_TRCU[19] = 0
 avg_TRCU_22[20]: - U[1,22] + Avg_TRCU[20] = 0
 avg_TRCU_22[21]: - U[1,22] + Avg_TRCU[21] = 0
 avg_TRCU_22[22]: - U[1,22] + Avg_TRCU[22] = 0
 avg_TRCU_22[23]: - U[1,22] + Avg_TRCU[23] = 0
 cooling_power_22: - 0.2857142857142857 H_1[22] + P_source[22] = 0
 total_cooling_power_22: - P_source[22] - P_fan[22] + P_cooling[22] = 0
 PS1_23: U[2,22] - 1.333333333333333 L_BW[0,23] - 100.5 A_DC[22]
   = 233.3333333333333
 PS2_23: U[3,22] - 1.333333333333333 L_BW[1,23] - 100.5 A_DC[22]
   = 233.3333333333333
 temp_dynamics_X_1_23[0]: rack_1[0,23] - 8.2918739635157504e-04 U[0,22]
   - 0.9121061359867327 U[1,22] - 0.0071198776435842 U[2,22] = 0
 temp_dynamics_X_1_23[1]: rack_1[1,23] - 8.2918739635157504e-04 U[0,22]
   - 0.9121061359867327 U[1,22] - 0.0071198776435842 U[3,22] = 0
 temp_dynamics_X_1_23[2]: rack_1[2,23] - 8.2918739635157504e-04 U[0,22]
   - 0.9121061359867327 U[1,22] - 0.0188398408428998 U[2,22] = 0
 temp_dynamics_X_1_23[3]: rack_1[3,23] - 8.2918739635157504e-04 U[0,22]
   - 0.9121061359867327 U[1,22] - 0.0188398408428998 U[3,22] = 0
 avg_TRCU_23[0]: - U[1,23] + Avg_TRCU[0] = 0
 avg_TRCU_23[1]: - U[1,23] + Avg_TRCU[1] = 0
 avg_TRCU_23[2]: - U[1,23] + Avg_TRCU[2] = 0
 avg_TRCU_23[3]: - U[1,23] + Avg_TRCU[3] = 0
 avg_TRCU_23[4]: - U[1,23] + Avg_TRCU[4] = 0
 avg_TRCU_23[5]: - U[1,23] + Avg_TRCU[5] = 0
 avg_TRCU_23[6]: - U[1,23] + Avg_TRCU[6] = 0
 avg_TRCU_23[7]: - U[1,23] + Avg_TRCU[7] = 0
 avg_TRCU_23[8]: - U[1,23] + Avg_TRCU[8] = 0
 avg_TRCU_23[9]: - U[1,23] + Avg_TRCU[9] = 0
 avg_TRCU_23[10]: - U[1,23] + Avg_TRCU[10] = 0
 avg_TRCU_23[11]: - U[1,23] + Avg_TRCU[11] = 0
 avg_TRCU_23[12]: - U[1,23] + Avg_TRCU[12] = 0
 avg_TRCU_23[13]: - U[1,23] + Avg_TRCU[13] = 0
 avg_TRCU_23[14]: - U[1,23] + Avg_TRCU[14] = 0
 avg_TRCU_23[15]: - U[1,23] + Avg_TRCU[15] = 0
 avg_TRCU_23[16]: - U[1,23] + Avg_TRCU[16] = 0
 avg_TRCU_23[17]: - U[1,23] + Avg_TRCU[17] = 0
 avg_TRCU_23[18]: - U[1,23] + Avg_TRCU[18] = 0
 avg_TRCU_23[19]: - U[1,23] + Avg_TRCU[19] = 0
 avg_TRCU_23[20]: - U[1,23] + Avg_TRCU[20] = 0
 avg_TRCU_23[21]: - U[1,23] + Avg_TRCU[21] = 0
 avg_TRCU_23[22]: - U[1,23] + Avg_TRCU[22] = 0
 avg_TRCU_23[23]: - U[1,23] + Avg_TRCU[23] = 0
 cooling_power_23: - 0.2857142857142857 H_1[23] + P_source[23] = 0
 total_cooling_power_23: - P_source[23] - P_fan[23] + P_cooling[23] = 0
 final_SoC_equals_initial: SoC[23] = 0.8
 power_balance_1: - 0.1005 A_DC[1] - 0.00133333333333333 L[1] + Pimp[1]
   - Pexp[1] - Pch[1] + Pdis[1] - 0.001 P_cooling[1] = 0
 discharge_power_limit_1: Pdis[1] - 2 epsilon_dis[1] <= 0
 charge_power_limit_1: Pch[1] - 2 epsilon_ch[1] <= 0
 battery_state_1: epsilon_ch[1] + epsilon_dis[1] <= 1
 SoC_1: - 0.99 SoC[0] + SoC[1] - 0.0684 Pch[1] + 0.08 Pdis[1] = 0
 heat_balance_1: H_sub[1] + H_1[1] = 3360.48973
 power_balance_2: - 0.1005 A_DC[2] - 0.00133333333333333 L[2] + Pimp[2]
   - Pexp[2] - Pch[2] + Pdis[2] - 0.001 P_cooling[2] = 0
 discharge_power_limit_2: Pdis[2] - 2 epsilon_dis[2] <= 0
 charge_power_limit_2: Pch[2] - 2 epsilon_ch[2] <= 0
 battery_state_2: epsilon_ch[2] + epsilon_dis[2] <= 1
 SoC_2: - 0.99 SoC[1] + SoC[2] - 0.0684 Pch[2] + 0.08 Pdis[2] = 0
 heat_balance_2: H_sub[2] + H_1[2] = 3463.889414
 power_balance_3: - 0.1005 A_DC[3] - 0.00133333333333333 L[3] + Pimp[3]
   - Pexp[3] - Pch[3] + Pdis[3] - 0.001 P_cooling[3] = 0
 discharge_power_limit_3: Pdis[3] - 2 epsilon_dis[3] <= 0
 charge_power_limit_3: Pch[3] - 2 epsilon_ch[3] <= 0
 battery_state_3: epsilon_ch[3] + epsilon_dis[3] <= 1
 SoC_3: - 0.99 SoC[2] + SoC[3] - 0.0684 Pch[3] + 0.08 Pdis[3] = 0
 heat_balance_3: H_sub[3] + H_1[3] = 3463.889414
 power_balance_4: - 0.1005 A_DC[4] - 0.00133333333333333 L[4] + Pimp[4]
   - Pexp[4] - Pch[4] + Pdis[4] - 0.001 P_cooling[4] = 0
 discharge_power_limit_4: Pdis[4] - 2 epsilon_dis[4] <= 0
 charge_power_limit_4: Pch[4] - 2 epsilon_ch[4] <= 0
 battery_state_4: epsilon_ch[4] + epsilon_dis[4] <= 1
 SoC_4: - 0.99 SoC[3] + SoC[4] - 0.0684 Pch[4] + 0.08 Pdis[4] = 0
 heat_balance_4: H_sub[4] + H_1[4] = 3412.189572
 power_balance_5: - 0.1005 A_DC[5] - 0.00133333333333333 L[5] + Pimp[5]
   - Pexp[5] - Pch[5] + Pdis[5] - 0.001 P_cooling[5] = 0
 discharge_power_limit_5: Pdis[5] - 2 epsilon_dis[5] <= 0
 charge_power_limit_5: Pch[5] - 2 epsilon_ch[5] <= 0
 battery_state_5: epsilon_ch[5] + epsilon_dis[5] <= 1
 SoC_5: - 0.99 SoC[4] + SoC[5] - 0.0684 Pch[5] + 0.08 Pdis[5] = 0
 heat_balance_5: H_sub[5] + H_1[5] = 3257.090046
 power_balance_6: - 0.1005 A_DC[6] - 0.00133333333333333 L[6] + Pimp[6]
   - Pexp[6] - Pch[6] + Pdis[6] - 0.001 P_cooling[6] = 0
 discharge_power_limit_6: Pdis[6] - 2 epsilon_dis[6] <= 0
 charge_power_limit_6: Pch[6] - 2 epsilon_ch[6] <= 0
 battery_state_6: epsilon_ch[6] + epsilon_dis[6] <= 1
 SoC_6: - 0.99 SoC[5] + SoC[6] - 0.0684 Pch[6] + 0.08 Pdis[6] = 0
 heat_balance_6: H_sub[6] + H_1[6] = 5682.711952
 power_balance_7: - 0.1005 A_DC[7] - 0.00133333333333333 L[7] + Pimp[7]
   - Pexp[7] - Pch[7] + Pdis[7] - 0.001 P_cooling[7] = 0
 discharge_power_limit_7: Pdis[7] - 2 epsilon_dis[7] <= 0
 charge_power_limit_7: Pch[7] - 2 epsilon_ch[7] <= 0
 battery_state_7: epsilon_ch[7] + epsilon_dis[7] <= 1
 SoC_7: - 0.99 SoC[6] + SoC[7] - 0.0684 Pch[7] + 0.08 Pdis[7] = 0
 heat_balance_7: H_sub[7] + H_1[7] = 5066.584516
 power_balance_8: - 0.1005 A_DC[8] - 0.00133333333333333 L[8] + Pimp[8]
   - Pexp[8] - Pch[8] + Pdis[8] - 0.001 P_cooling[8] = -0.05985114
 discharge_power_limit_8: Pdis[8] - 2 epsilon_dis[8] <= 0
 charge_power_limit_8: Pch[8] - 2 epsilon_ch[8] <= 0
 battery_state_8: epsilon_ch[8] + epsilon_dis[8] <= 1
 SoC_8: - 0.99 SoC[7] + SoC[8] - 0.0684 Pch[8] + 0.08 Pdis[8] = 0
 heat_balance_8: H_sub[8] + H_1[8] = 5118.284358000001
 power_balance_9: - 0.1005 A_DC[9] - 0.00133333333333333 L[9] + Pimp[9]
   - Pexp[9] - Pch[9] + Pdis[9] - 0.001 P_cooling[9] = -0.39961481625
 discharge_power_limit_9: Pdis[9] - 2 epsilon_dis[9] <= 0
 charge_power_limit_9: Pch[9] - 2 epsilon_ch[9] <= 0
 battery_state_9: epsilon_ch[9] + epsilon_dis[9] <= 1
 SoC_9: - 0.99 SoC[8] + SoC[9] - 0.0684 Pch[9] + 0.08 Pdis[9] = 0
 heat_balance_9: H_sub[9] + H_1[9] = 0
 power_balance_10: - 0.1005 A_DC[10] - 0.00133333333333333 L[10] + Pimp[10]
   - Pexp[10] - Pch[10] + Pdis[10] - 0.001 P_cooling[10] = -0.73909696
 discharge_power_limit_10: Pdis[10] - 2 epsilon_dis[10] <= 0
 charge_power_limit_10: Pch[10] - 2 epsilon_ch[10] <= 0
 battery_state_10: epsilon_ch[10] + epsilon_dis[10] <= 1
 SoC_10: - 0.99 SoC[9] + SoC[10] - 0.0684 Pch[10] + 0.08 Pdis[10] = 0
 heat_balance_10: H_sub[10] + H_1[10] = 0
 power_balance_11: - 0.1005 A_DC[11] - 0.00133333333333333 L[11] + Pimp[11]
   - Pexp[11] - Pch[11] + Pdis[11] - 0.001 P_cooling[11] = -0.934336495
 discharge_power_limit_11: Pdis[11] - 2 epsilon_dis[11] <= 0
 charge_power_limit_11: Pch[11] - 2 epsilon_ch[11] <= 0
 battery_state_11: epsilon_ch[11] + epsilon_dis[11] <= 1
 SoC_11: - 0.99 SoC[10] + SoC[11] - 0.0684 Pch[11] + 0.08 Pdis[11] = 0
 heat_balance_11: H_sub[11] + H_1[11] = 0
 power_balance_12: - 0.1005 A_DC[12] - 0.00133333333333333 L[12] + Pimp[12]
   - Pexp[12] - Pch[12] + Pdis[12] - 0.001 P_cooling[12] = -0.51257784375
 discharge_power_limit_12: Pdis[12] - 2 epsilon_dis[12] <= 0
 charge_power_limit_12: Pch[12] - 2 epsilon_ch[12] <= 0
 battery_state_12: epsilon_ch[12] + epsilon_dis[12] <= 1
 SoC_12: - 0.99 SoC[11] + SoC[12] - 0.0684 Pch[12] + 0.08 Pdis[12] = 0
 heat_balance_12: H_sub[12] + H_1[12] = 0
 power_balance_13: - 0.1005 A_DC[13] - 0.00133333333333333 L[13] + Pimp[13]
   - Pexp[13] - Pch[13] + Pdis[13] - 0.001 P_cooling[13] = -0.51257784375
 discharge_power_limit_13: Pdis[13] - 2 epsilon_dis[13] <= 0
 charge_power_limit_13: Pch[13] - 2 epsilon_ch[13] <= 0
 battery_state_13: epsilon_ch[13] + epsilon_dis[13] <= 1
 SoC_13: - 0.99 SoC[12] + SoC[13] - 0.0684 Pch[13] + 0.08 Pdis[13] = 0
 heat_balance_13: H_sub[13] + H_1[13] = 0
 power_balance_14: - 0.1005 A_DC[14] - 0.00133333333333333 L[14] + Pimp[14]
   - Pexp[14] - Pch[14] + Pdis[14] - 0.001 P_cooling[14] = -0.33866571375
 discharge_power_limit_14: Pdis[14] - 2 epsilon_dis[14] <= 0
 charge_power_limit_14: Pch[14] - 2 epsilon_ch[14] <= 0
 battery_state_14: epsilon_ch[14] + epsilon_dis[14] <= 1
 SoC_14: - 0.99 SoC[13] + SoC[14] - 0.0684 Pch[14] + 0.08 Pdis[14] = 0
 heat_balance_14: H_sub[14] + H_1[14] = 0
 power_balance_15: - 0.1005 A_DC[15] - 0.00133333333333333 L[15] + Pimp[15]
   - Pexp[15] - Pch[15] + Pdis[15] - 0.001 P_cooling[15] = -0.08440636
 discharge_power_limit_15: Pdis[15] - 2 epsilon_dis[15] <= 0
 charge_power_limit_15: Pch[15] - 2 epsilon_ch[15] <= 0
 battery_state_15: epsilon_ch[15] + epsilon_dis[15] <= 1
 SoC_15: - 0.99 SoC[14] + SoC[15] - 0.0684 Pch[15] + 0.08 Pdis[15] = 0
 heat_balance_15: H_sub[15] + H_1[15] = 464.444444
 power_balance_16: - 0.1005 A_DC[16] - 0.00133333333333333 L[16] + Pimp[16]
   - Pexp[16] - Pch[16] + Pdis[16] - 0.001 P_cooling[16] = 0
 discharge_power_limit_16: Pdis[16] - 2 epsilon_dis[16] <= 0
 charge_power_limit_16: Pch[16] - 2 epsilon_ch[16] <= 0
 battery_state_16: epsilon_ch[16] + epsilon_dis[16] <= 1
 SoC_16: - 0.99 SoC[15] + SoC[16] - 0.0684 Pch[16] + 0.08 Pdis[16] = 0
 heat_balance_16: H_sub[16] + H_1[16] = 0
 power_balance_17: - 0.1005 A_DC[17] - 0.00133333333333333 L[17] + Pimp[17]
   - Pexp[17] - Pch[17] + Pdis[17] - 0.001 P_cooling[17] = 0
 discharge_power_limit_17: Pdis[17] - 2 epsilon_dis[17] <= 0
 charge_power_limit_17: Pch[17] - 2 epsilon_ch[17] <= 0
 battery_state_17: epsilon_ch[17] + epsilon_dis[17] <= 1
 SoC_17: - 0.99 SoC[16] + SoC[17] - 0.0684 Pch[17] + 0.08 Pdis[17] = 0
 heat_balance_17: H_sub[17] + H_1[17] = 0
 power_balance_18: - 0.1005 A_DC[18] - 0.00133333333333333 L[18] + Pimp[18]
   - Pexp[18] - Pch[18] + Pdis[18] - 0.001 P_cooling[18] = 0
 discharge_power_limit_18: Pdis[18] - 2 epsilon_dis[18] <= 0
 charge_power_limit_18: Pch[18] - 2 epsilon_ch[18] <= 0
 battery_state_18: epsilon_ch[18] + epsilon_dis[18] <= 1
 SoC_18: - 0.99 SoC[17] + SoC[18] - 0.0684 Pch[18] + 0.08 Pdis[18] = 0
 heat_balance_18: H_sub[18] + H_1[18] = 4865.286728
 power_balance_19: - 0.1005 A_DC[19] - 0.00133333333333333 L[19] + Pimp[19]
   - Pexp[19] - Pch[19] + Pdis[19] - 0.001 P_cooling[19] = 0
 discharge_power_limit_19: Pdis[19] - 2 epsilon_dis[19] <= 0
 charge_power_limit_19: Pch[19] - 2 epsilon_ch[19] <= 0
 battery_state_19: epsilon_ch[19] + epsilon_dis[19] <= 1
 SoC_19: - 0.99 SoC[18] + SoC[19] - 0.0684 Pch[19] + 0.08 Pdis[19] = 0
 heat_balance_19: H_sub[19] + H_1[19] = 4601.285938
 power_balance_20: - 0.1005 A_DC[20] - 0.00133333333333333 L[20] + Pimp[20]
   - Pexp[20] - Pch[20] + Pdis[20] - 0.001 P_cooling[20] = 0
 discharge_power_limit_20: Pdis[20] - 2 epsilon_dis[20] <= 0
 charge_power_limit_20: Pch[20] - 2 epsilon_ch[20] <= 0
 battery_state_20: epsilon_ch[20] + epsilon_dis[20] <= 1
 SoC_20: - 0.99 SoC[19] + SoC[20] - 0.0684 Pch[20] + 0.08 Pdis[20] = 0
 heat_balance_20: H_sub[20] + H_1[20] = 4601.285938
 power_balance_21: - 0.1005 A_DC[21] - 0.00133333333333333 L[21] + Pimp[21]
   - Pexp[21] - Pch[21] + Pdis[21] - 0.001 P_cooling[21] = 0
 discharge_power_limit_21: Pdis[21] - 2 epsilon_dis[21] <= 0
 charge_power_limit_21: Pch[21] - 2 epsilon_ch[21] <= 0
 battery_state_21: epsilon_ch[21] + epsilon_dis[21] <= 1
 SoC_21: - 0.99 SoC[20] + SoC[21] - 0.0684 Pch[21] + 0.08 Pdis[21] = 0
 heat_balance_21: H_sub[21] + H_1[21] = 5181.841493
 power_balance_22: - 0.1005 A_DC[22] - 0.00133333333333333 L[22] + Pimp[22]
   - Pexp[22] - Pch[22] + Pdis[22] - 0.001 P_cooling[22] = 0
 discharge_power_limit_22: Pdis[22] - 2 epsilon_dis[22] <= 0
 charge_power_limit_22: Pch[22] - 2 epsilon_ch[22] <= 0
 battery_state_22: epsilon_ch[22] + epsilon_dis[22] <= 1
 SoC_22: - 0.99 SoC[21] + SoC[22] - 0.0684 Pch[22] + 0.08 Pdis[22] = 0
 heat_balance_22: H_sub[22] + H_1[22] = 5227.185622
 power_balance_23: - 0.1005 A_DC[23] - 0.00133333333333333 L[23] + Pimp[23]
   - Pexp[23] - Pch[23] + Pdis[23] - 0.001 P_cooling[23] = 0
 discharge_power_limit_23: Pdis[23] - 2 epsilon_dis[23] <= 0
 charge_power_limit_23: Pch[23] - 2 epsilon_ch[23] <= 0
 battery_state_23: epsilon_ch[23] + epsilon_dis[23] <= 1
 SoC_23: - 0.99 SoC[22] + SoC[23] - 0.0684 Pch[23] + 0.08 Pdis[23] = 0
 heat_balance_23: H_sub[23] + H_1[23] = 2274.793048
 waste_heat_recovery_1: H_1[1] + [ - 603 rack_1[2,1] * U[1,1]
   - 603 rack_1[3,1] * U[1,1] + 1206 U[0,1] * U[1,1] ] = 0
 fan_power_1: 3073 U[1,1] + P_fan[1] + [ - 6031 U[1,1] ^2 ] = 480
 waste_heat_recovery_2: H_1[2] + [ - 603 rack_1[2,2] * U[1,2]
   - 603 rack_1[3,2] * U[1,2] + 1206 U[0,2] * U[1,2] ] = 0
 fan_power_2: 3073 U[1,2] + P_fan[2] + [ - 6031 U[1,2] ^2 ] = 480
 waste_heat_recovery_3: H_1[3] + [ - 603 rack_1[2,3] * U[1,3]
   - 603 rack_1[3,3] * U[1,3] + 1206 U[0,3] * U[1,3] ] = 0
 fan_power_3: 3073 U[1,3] + P_fan[3] + [ - 6031 U[1,3] ^2 ] = 480
 waste_heat_recovery_4: H_1[4] + [ - 603 rack_1[2,4] * U[1,4]
   - 603 rack_1[3,4] * U[1,4] + 1206 U[0,4] * U[1,4] ] = 0
 fan_power_4: 3073 U[1,4] + P_fan[4] + [ - 6031 U[1,4] ^2 ] = 480
 waste_heat_recovery_5: H_1[5] + [ - 603 rack_1[2,5] * U[1,5]
   - 603 rack_1[3,5] * U[1,5] + 1206 U[0,5] * U[1,5] ] = 0
 fan_power_5: 3073 U[1,5] + P_fan[5] + [ - 6031 U[1,5] ^2 ] = 480
 waste_heat_recovery_6: H_1[6] + [ - 603 rack_1[2,6] * U[1,6]
   - 603 rack_1[3,6] * U[1,6] + 1206 U[0,6] * U[1,6] ] = 0
 fan_power_6: 3073 U[1,6] + P_fan[6] + [ - 6031 U[1,6] ^2 ] = 480
 waste_heat_recovery_7: H_1[7] + [ - 603 rack_1[2,7] * U[1,7]
   - 603 rack_1[3,7] * U[1,7] + 1206 U[0,7] * U[1,7] ] = 0
 fan_power_7: 3073 U[1,7] + P_fan[7] + [ - 6031 U[1,7] ^2 ] = 480
 waste_heat_recovery_8: H_1[8] + [ - 603 rack_1[2,8] * U[1,8]
   - 603 rack_1[3,8] * U[1,8] + 1206 U[0,8] * U[1,8] ] = 0
 fan_power_8: 3073 U[1,8] + P_fan[8] + [ - 6031 U[1,8] ^2 ] = 480
 waste_heat_recovery_9: H_1[9] + [ - 603 rack_1[2,9] * U[1,9]
   - 603 rack_1[3,9] * U[1,9] + 1206 U[0,9] * U[1,9] ] = 0
 fan_power_9: 3073 U[1,9] + P_fan[9] + [ - 6031 U[1,9] ^2 ] = 480
 waste_heat_recovery_10: H_1[10] + [ - 603 rack_1[2,10] * U[1,10]
   - 603 rack_1[3,10] * U[1,10] + 1206 U[0,10] * U[1,10] ] = 0
 fan_power_10: 3073 U[1,10] + P_fan[10] + [ - 6031 U[1,10] ^2 ] = 480
 waste_heat_recovery_11: H_1[11] + [ - 603 rack_1[2,11] * U[1,11]
   - 603 rack_1[3,11] * U[1,11] + 1206 U[0,11] * U[1,11] ] = 0
 fan_power_11: 3073 U[1,11] + P_fan[11] + [ - 6031 U[1,11] ^2 ] = 480
 waste_heat_recovery_12: H_1[12] + [ - 603 rack_1[2,12] * U[1,12]
   - 603 rack_1[3,12] * U[1,12] + 1206 U[0,12] * U[1,12] ] = 0
 fan_power_12: 3073 U[1,12] + P_fan[12] + [ - 6031 U[1,12] ^2 ] = 480
 waste_heat_recovery_13: H_1[13] + [ - 603 rack_1[2,13] * U[1,13]
   - 603 rack_1[3,13] * U[1,13] + 1206 U[0,13] * U[1,13] ] = 0
 fan_power_13: 3073 U[1,13] + P_fan[13] + [ - 6031 U[1,13] ^2 ] = 480
 waste_heat_recovery_14: H_1[14] + [ - 603 rack_1[2,14] * U[1,14]
   - 603 rack_1[3,14] * U[1,14] + 1206 U[0,14] * U[1,14] ] = 0
 fan_power_14: 3073 U[1,14] + P_fan[14] + [ - 6031 U[1,14] ^2 ] = 480
 waste_heat_recovery_15: H_1[15] + [ - 603 rack_1[2,15] * U[1,15]
   - 603 rack_1[3,15] * U[1,15] + 1206 U[0,15] * U[1,15] ] = 0
 fan_power_15: 3073 U[1,15] + P_fan[15] + [ - 6031 U[1,15] ^2 ] = 480
 waste_heat_recovery_16: H_1[16] + [ - 603 rack_1[2,16] * U[1,16]
   - 603 rack_1[3,16] * U[1,16] + 1206 U[0,16] * U[1,16] ] = 0
 fan_power_16: 3073 U[1,16] + P_fan[16] + [ - 6031 U[1,16] ^2 ] = 480
 waste_heat_recovery_17: H_1[17] + [ - 603 rack_1[2,17] * U[1,17]
   - 603 rack_1[3,17] * U[1,17] + 1206 U[0,17] * U[1,17] ] = 0
 fan_power_17: 3073 U[1,17] + P_fan[17] + [ - 6031 U[1,17] ^2 ] = 480
 waste_heat_recovery_18: H_1[18] + [ - 603 rack_1[2,18] * U[1,18]
   - 603 rack_1[3,18] * U[1,18] + 1206 U[0,18] * U[1,18] ] = 0
 fan_power_18: 3073 U[1,18] + P_fan[18] + [ - 6031 U[1,18] ^2 ] = 480
 waste_heat_recovery_19: H_1[19] + [ - 603 rack_1[2,19] * U[1,19]
   - 603 rack_1[3,19] * U[1,19] + 1206 U[0,19] * U[1,19] ] = 0
 fan_power_19: 3073 U[1,19] + P_fan[19] + [ - 6031 U[1,19] ^2 ] = 480
 waste_heat_recovery_20: H_1[20] + [ - 603 rack_1[2,20] * U[1,20]
   - 603 rack_1[3,20] * U[1,20] + 1206 U[0,20] * U[1,20] ] = 0
 fan_power_20: 3073 U[1,20] + P_fan[20] + [ - 6031 U[1,20] ^2 ] = 480
 waste_heat_recovery_21: H_1[21] + [ - 603 rack_1[2,21] * U[1,21]
   - 603 rack_1[3,21] * U[1,21] + 1206 U[0,21] * U[1,21] ] = 0
 fan_power_21: 3073 U[1,21] + P_fan[21] + [ - 6031 U[1,21] ^2 ] = 480
 waste_heat_recovery_22: H_1[22] + [ - 603 rack_1[2,22] * U[1,22]
   - 603 rack_1[3,22] * U[1,22] + 1206 U[0,22] * U[1,22] ] = 0
 fan_power_22: 3073 U[1,22] + P_fan[22] + [ - 6031 U[1,22] ^2 ] = 480
 waste_heat_recovery_23: H_1[23] + [ - 603 rack_1[2,23] * U[1,23]
   - 603 rack_1[3,23] * U[1,23] + 1206 U[0,23] * U[1,23] ] = 0
 fan_power_23: 3073 U[1,23] + P_fan[23] + [ - 6031 U[1,23] ^2 ] = 480
Bounds
 U[0,0] <= 60
 U[0,1] <= 60
 U[0,2] <= 60
 U[0,3] <= 60
 U[0,4] <= 60
 U[0,5] <= 60
 U[0,6] <= 60
 U[0,7] <= 60
 U[0,8] <= 60
 U[0,9] <= 60
 U[0,10] <= 60
 U[0,11] <= 60
 U[0,12] <= 60
 U[0,13] <= 60
 U[0,14] <= 60
 U[0,15] <= 60
 U[0,16] <= 60
 U[0,17] <= 60
 U[0,18] <= 60
 U[0,19] <= 60
 U[0,20] <= 60
 U[0,21] <= 60
 U[0,22] <= 60
 U[0,23] <= 60
 U[1,0] <= 0.1
 U[1,1] <= 0.1
 U[1,2] <= 0.1
 U[1,3] <= 0.1
 U[1,4] <= 0.1
 U[1,5] <= 0.1
 U[1,6] <= 0.1
 U[1,7] <= 0.1
 U[1,8] <= 0.1
 U[1,9] <= 0.1
 U[1,10] <= 0.1
 U[1,11] <= 0.1
 U[1,12] <= 0.1
 U[1,13] <= 0.1
 U[1,14] <= 0.1
 U[1,15] <= 0.1
 U[1,16] <= 0.1
 U[1,17] <= 0.1
 U[1,18] <= 0.1
 U[1,19] <= 0.1
 U[1,20] <= 0.1
 U[1,21] <= 0.1
 U[1,22] <= 0.1
 U[1,23] <= 0.1
 U[2,0] <= 2500
 U[2,1] <= 2500
 U[2,2] <= 2500
 U[2,3] <= 2500
 U[2,4] <= 2500
 U[2,5] <= 2500
 U[2,6] <= 2500
 U[2,7] <= 2500
 U[2,8] <= 2500
 U[2,9] <= 2500
 U[2,10] <= 2500
 U[2,11] <= 2500
 U[2,12] <= 2500
 U[2,13] <= 2500
 U[2,14] <= 2500
 U[2,15] <= 2500
 U[2,16] <= 2500
 U[2,17] <= 2500
 U[2,18] <= 2500
 U[2,19] <= 2500
 U[2,20] <= 2500
 U[2,21] <= 2500
 U[2,22] <= 2500
 U[2,23] <= 2500
 U[3,0] <= 2500
 U[3,1] <= 2500
 U[3,2] <= 2500
 U[3,3] <= 2500
 U[3,4] <= 2500
 U[3,5] <= 2500
 U[3,6] <= 2500
 U[3,7] <= 2500
 U[3,8] <= 2500
 U[3,9] <= 2500
 U[3,10] <= 2500
 U[3,11] <= 2500
 U[3,12] <= 2500
 U[3,13] <= 2500
 U[3,14] <= 2500
 U[3,15] <= 2500
 U[3,16] <= 2500
 U[3,17] <= 2500
 U[3,18] <= 2500
 U[3,19] <= 2500
 U[3,20] <= 2500
 U[3,21] <= 2500
 U[3,22] <= 2500
 U[3,23] <= 2500
 L_BW[0,0] <= 1527.916666666667
 L_BW[0,1] <= 1527.916666666667
 L_BW[0,2] <= 1527.916666666667
 L_BW[0,3] <= 1527.916666666667
 L_BW[0,4] <= 1527.916666666667
 L_BW[0,5] <= 1527.916666666667
 L_BW[0,6] <= 1527.916666666667
 L_BW[0,7] <= 1527.916666666667
 L_BW[0,8] <= 1527.916666666667
 L_BW[0,9] <= 1527.916666666667
 L_BW[0,10] <= 1527.916666666667
 L_BW[0,11] <= 1527.916666666667
 L_BW[0,12] <= 1527.916666666667
 L_BW[0,13] <= 1527.916666666667
 L_BW[0,14] <= 1527.916666666667
 L_BW[0,15] <= 1527.916666666667
 L_BW[0,16] <= 1527.916666666667
 L_BW[0,17] <= 1527.916666666667
 L_BW[0,18] <= 1527.916666666667
 L_BW[0,19] <= 1527.916666666667
 L_BW[0,20] <= 1527.916666666667
 L_BW[0,21] <= 1527.916666666667
 L_BW[0,22] <= 1527.916666666667
 L_BW[0,23] <= 1527.916666666667
 L_BW[1,0] <= 1527.916666666667
 L_BW[1,1] <= 1527.916666666667
 L_BW[1,2] <= 1527.916666666667
 L_BW[1,3] <= 1527.916666666667
 L_BW[1,4] <= 1527.916666666667
 L_BW[1,5] <= 1527.916666666667
 L_BW[1,6] <= 1527.916666666667
 L_BW[1,7] <= 1527.916666666667
 L_BW[1,8] <= 1527.916666666667
 L_BW[1,9] <= 1527.916666666667
 L_BW[1,10] <= 1527.916666666667
 L_BW[1,11] <= 1527.916666666667
 L_BW[1,12] <= 1527.916666666667
 L_BW[1,13] <= 1527.916666666667
 L_BW[1,14] <= 1527.916666666667
 L_BW[1,15] <= 1527.916666666667
 L_BW[1,16] <= 1527.916666666667
 L_BW[1,17] <= 1527.916666666667
 L_BW[1,18] <= 1527.916666666667
 L_BW[1,19] <= 1527.916666666667
 L_BW[1,20] <= 1527.916666666667
 L_BW[1,21] <= 1527.916666666667
 L_BW[1,22] <= 1527.916666666667
 L_BW[1,23] <= 1527.916666666667
 A_DC[0] <= 10
 A_DC[1] <= 10
 A_DC[2] <= 10
 A_DC[3] <= 10
 A_DC[4] <= 10
 A_DC[5] <= 10
 A_DC[6] <= 10
 A_DC[7] <= 10
 A_DC[8] <= 10
 A_DC[9] <= 10
 A_DC[10] <= 10
 A_DC[11] <= 10
 A_DC[12] <= 10
 A_DC[13] <= 10
 A_DC[14] <= 10
 A_DC[15] <= 10
 A_DC[16] <= 10
 A_DC[17] <= 10
 A_DC[18] <= 10
 A_DC[19] <= 10
 A_DC[20] <= 10
 A_DC[21] <= 10
 A_DC[22] <= 10
 A_DC[23] <= 10
 0.5 <= SoC[0] <= 0.9
 0.5 <= SoC[1] <= 0.9
 0.5 <= SoC[2] <= 0.9
 0.5 <= SoC[3] <= 0.9
 0.5 <= SoC[4] <= 0.9
 0.5 <= SoC[5] <= 0.9
 0.5 <= SoC[6] <= 0.9
 0.5 <= SoC[7] <= 0.9
 0.5 <= SoC[8] <= 0.9
 0.5 <= SoC[9] <= 0.9
 0.5 <= SoC[10] <= 0.9
 0.5 <= SoC[11] <= 0.9
 0.5 <= SoC[12] <= 0.9
 0.5 <= SoC[13] <= 0.9
 0.5 <= SoC[14] <= 0.9
 0.5 <= SoC[15] <= 0.9
 0.5 <= SoC[16] <= 0.9
 0.5 <= SoC[17] <= 0.9
 0.5 <= SoC[18] <= 0.9
 0.5 <= SoC[19] <= 0.9
 0.5 <= SoC[20] <= 0.9
 0.5 <= SoC[21] <= 0.9
 0.5 <= SoC[22] <= 0.9
 0.5 <= SoC[23] <= 0.9
 Pimp[0] <= 5
 Pimp[1] <= 5
 Pimp[2] <= 5
 Pimp[3] <= 5
 Pimp[4] <= 5
 Pimp[5] <= 5
 Pimp[6] <= 5
 Pimp[7] <= 5
 Pimp[8] <= 5
 Pimp[9] <= 5
 Pimp[10] <= 5
 Pimp[11] <= 5
 Pimp[12] <= 5
 Pimp[13] <= 5
 Pimp[14] <= 5
 Pimp[15] <= 5
 Pimp[16] <= 5
 Pimp[17] <= 5
 Pimp[18] <= 5
 Pimp[19] <= 5
 Pimp[20] <= 5
 Pimp[21] <= 5
 Pimp[22] <= 5
 Pimp[23] <= 5
 Pexp[0] <= 5
 Pexp[1] <= 5
 Pexp[2] <= 5
 Pexp[3] <= 5
 Pexp[4] <= 5
 Pexp[5] <= 5
 Pexp[6] <= 5
 Pexp[7] <= 5
 Pexp[8] <= 5
 Pexp[9] <= 5
 Pexp[10] <= 5
 Pexp[11] <= 5
 Pexp[12] <= 5
 Pexp[13] <= 5
 Pexp[14] <= 5
 Pexp[15] <= 5
 Pexp[16] <= 5
 Pexp[17] <= 5
 Pexp[18] <= 5
 Pexp[19] <= 5
 Pexp[20] <= 5
 Pexp[21] <= 5
 Pexp[22] <= 5
 Pexp[23] <= 5
 Pch[0] <= 2
 Pch[1] <= 2
 Pch[2] <= 2
 Pch[3] <= 2
 Pch[4] <= 2
 Pch[5] <= 2
 Pch[6] <= 2
 Pch[7] <= 2
 Pch[8] <= 2
 Pch[9] <= 2
 Pch[10] <= 2
 Pch[11] <= 2
 Pch[12] <= 2
 Pch[13] <= 2
 Pch[14] <= 2
 Pch[15] <= 2
 Pch[16] <= 2
 Pch[17] <= 2
 Pch[18] <= 2
 Pch[19] <= 2
 Pch[20] <= 2
 Pch[21] <= 2
 Pch[22] <= 2
 Pch[23] <= 2
 Pdis[0] <= 2
 Pdis[1] <= 2
 Pdis[2] <= 2
 Pdis[3] <= 2
 Pdis[4] <= 2
 Pdis[5] <= 2
 Pdis[6] <= 2
 Pdis[7] <= 2
 Pdis[8] <= 2
 Pdis[9] <= 2
 Pdis[10] <= 2
 Pdis[11] <= 2
 Pdis[12] <= 2
 Pdis[13] <= 2
 Pdis[14] <= 2
 Pdis[15] <= 2
 Pdis[16] <= 2
 Pdis[17] <= 2
 Pdis[18] <= 2
 Pdis[19] <= 2
 Pdis[20] <= 2
 Pdis[21] <= 2
 Pdis[22] <= 2
 Pdis[23] <= 2
Binaries
 epsilon_ch[0] epsilon_ch[1] epsilon_ch[2] epsilon_ch[3] epsilon_ch[4]
 epsilon_ch[5] epsilon_ch[6] epsilon_ch[7] epsilon_ch[8] epsilon_ch[9]
 epsilon_ch[10] epsilon_ch[11] epsilon_ch[12] epsilon_ch[13] epsilon_ch[14]
 epsilon_ch[15] epsilon_ch[16] epsilon_ch[17] epsilon_ch[18] epsilon_ch[19]
 epsilon_ch[20] epsilon_ch[21] epsilon_ch[22] epsilon_ch[23] epsilon_dis[0]
 epsilon_dis[1] epsilon_dis[2] epsilon_dis[3] epsilon_dis[4] epsilon_dis[5]
 epsilon_dis[6] epsilon_dis[7] epsilon_dis[8] epsilon_dis[9]
 epsilon_dis[10] epsilon_dis[11] epsilon_dis[12] epsilon_dis[13]
 epsilon_dis[14] epsilon_dis[15] epsilon_dis[16] epsilon_dis[17]
 epsilon_dis[18] epsilon_dis[19] epsilon_dis[20] epsilon_dis[21]
 epsilon_dis[22] epsilon_dis[23]
End
