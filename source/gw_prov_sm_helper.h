/*********************************************************************
 * Copyright 2018-2019 ARRIS Enterprises, LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **********************************************************************/

#ifndef  _GW_PROV_SM_HELPER_H
#define  _GW_PROV_SM_HELPER_H

#include <sysevent/sysevent.h>
#include <sys_types.h>
#include "gw_prov_abstraction.h"

// for multinet
#define LGI_SUBNET3_INSTANCE  "6"
#define LGI_SUBNET4_INSTANCE  "7"
#define LGI_SUBNET5_INSTANCE  "8"
#define LGI_SUBNET6_INSTANCE  "9"
#define LGI_SUBNET7_INSTANCE  "10"
#define LGI_SUBNET8_INSTANCE  "11"
#define LGI_SUBNET9_INSTANCE  "12"
#define LGI_SUBNET10_INSTANCE  "13"

//Contants, types, and globals for TLV202.43.12 processing
#define MAX_DM_OBJ_RETRIES  120
#define DEVICE_WIFI "Device.WiFi."
#define DEVICE_WIFI_APPLY "ApplySetting"
#define DEVICE_HOTSPOT "Device.X_COMCAST-COM_GRE."
#define TLV2024312_CONFIG_DONE "CFG_DONE"
#define RESTART_MODULE              "restart_module"
#define RESTART_NONE                1
#define RESTART_WIFI                (1<<1)
#define RESTART_HOTSPOT             (1<<2)

extern DOCSIS_Esafe_Db_extIf_e eRouterMode;
extern DOCSIS_Esafe_Db_extIf_e oldRouterMode;
extern int sysevent_fd_gs;
extern token_t sysevent_token_gs;
extern int cfgFileRouterMode;

int Restart_Services(char *restart_module);
int RestartServicesPerMask(void);
void GW_TranslateGWmode2String( int gwmode, char *modestring, size_t len);
void GWP_UpdateERouterMode(void);
int GWP_SysCfgGetInt(const char *name);
void translateErouterSnmpInitModeToOperMode(esafeErouterInitModeExtIf_e initMode, DOCSIS_Esafe_Db_extIf_e *operMode);
void *GWP_start_hotspot_threadfunc(void *data);
void GWP_Update_ErouterMode_by_InitMode(void);
int GWP_act_ErouterSnmpInitModeSet_callback(void);
TlvParseCallbackStatusExtIf_e GW_VendorSpecificSubTLVParse(unsigned char type, unsigned short length, const unsigned char* value);

#endif
