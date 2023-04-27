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

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>

#include <ccsp_base_api.h>
#include <custom_alias_utils.h>
#include <syscfg/syscfg.h>
#include <ansc_platform.h>

#include "gw_prov_sm.h"
#include "gw_prov_sm_helper.h"

#include <cm_hal.h>

typedef struct _DmObject
{
    char Name[256];
    char Type[16];
    char Value[256];
    int  FailureCount;
    bool IsAliasBased;
    struct _DmObject *pNext;
} DmObject_t;

int cfgFileRouterMode = -1;
static void *bus_handle = NULL;

#define MAX_ARGS 20
#define MAX_LINE_SIZE 512
#define MAX_LEN 16
#define DHCPV4_PID_FILE "/var/run/eRT_ti_udhcpc.pid"
#define DHCPV6_PID_FILE "/var/run/erouter_dhcp6c.pid"

#define CR_COMPONENT_ID "eRT.com.cisco.spvtg.ccsp.CR"
#define SUBSYSTEM_PREFIX "eRT."

#define WIFI_SSID               "Device.WiFi.SSID."
#define WIFI_ACCESSPOINT        "Device.WiFi.AccessPoint."
#define WIFI_RADIO              "Device.WiFi.Radio."
#define WIFI_ATM                "Device.WiFi.X_LGI-COM_ATM.Radio."
#define WIFI_ATM_SSID_RADIO1    "Device.WiFi.X_LGI-COM_ATM.Radio.1.SSID."
#define WIFI_ATM_SSID_RADIO2    "Device.WiFi.X_LGI-COM_ATM.Radio.2.SSID."

#define RADIO_1_TR069_INDEX     10000
#define RADIO_2_TR069_INDEX     10100
#define RADIO_1_CCSP_INDEX      1
#define RADIO_2_CCSP_INDEX      2

#define NUMBER_OF_DATA_MODELS   6
#define MAX_DATAMODEL_SIZE      256

typedef struct ccsp_pair {
  char              *name;
  enum dataType_e   type;
} CCSP_PAIR;

static CCSP_PAIR ccsp_type_table[] = {
  { "string",   ccsp_string },
  { "int",      ccsp_int },
  { "uint",     ccsp_unsignedInt },
  { "bool",     ccsp_boolean },
  { "dateTime", ccsp_dateTime },
  { "base64",   ccsp_base64 },
  { "long",     ccsp_long },
  { "ulong",    ccsp_unsignedLong },
  { "float",    ccsp_float },
  { "double",   ccsp_double },
  { "byte",     ccsp_byte },
  { "hexBinary",ccsp_hexBinary}
};

#define NUM_CCSP_TYPES (sizeof(ccsp_type_table)/sizeof(ccsp_type_table[0]))

// globals for TLV202.43.12 processing
static DmObject_t *gpDmObjectHead = NULL;
static DmObject_t *gpDmObjectHeadAlias = NULL;    /* Sorted list for parameter with object instance number/alias */
static bool gbDmObjectParseCfgDone = false;
static int DmObjectSockFds[2];

static void Send_Release(char *file_name);
//static bool GW_HandleAliasDm((void* bus_handle, DmObject_t dmObject, int objectListAddNeeded);
static bool init_message_bus(void);
static bool isAliasMatch(char *object_name, char *parent, char *alias);
static bool isParentMatch(char *object_name, char *parent);
static void GW_HandleAliasDmList(void* bus_handle);
static int getIndex(char *lineOutput, char *parent);

/**************************************************************************/
/*! \fn bool ccsp_type_from_name(har *name, enum dataType_e *type_ptr)
 **************************************************************************
 *  \brief Get CCSP equivalent for paramter type
 *  \return bool 
 **************************************************************************/
static bool ccsp_type_from_name(char *name, enum dataType_e *type_ptr)
{
  int i;
  if(name == NULL)
     return false;
  for (i = 0 ; i < NUM_CCSP_TYPES ; ++i)
  {
      if ( 0 == strcmp(name, ccsp_type_table[i].name) )
      {
          *type_ptr = ccsp_type_table[i].type;
          return true;
      }
  }
  return false;
}

/**************************************************************************/
/*! \fn int GW_SetParameterValue(const char *pName, const char *pType, const char *pValue);
 **************************************************************************
 *  \brief Set DM paramter value
 *  \param[in] bus_handle - CCSP bus handle
 *  \param[in] pName - Parameter Name
 *  \param[in] pType - Parameter Type 
 *  \param[in] pValue - Parameter Value
 *  \return int - 0-success 
 *                1-set param value error 
 *                2-Issues with component discovery, input params
 **************************************************************************/

static int GW_SetParameterValue(void* bus_handle, const char *pName, const char *pType, const char *pValue)
{
    componentStruct_t ** ppComponents = NULL;
    int size = 0;
    char *dst_componentid =  NULL;
    char *dst_pathname    =  NULL;
    parameterValStruct_t param_val[1] = {0};
    char* pFaultParameter = NULL;
    int FailureCount = 0;
    int retVal=1;
    int ret;

    if ((bus_handle == NULL) || (pName == NULL) || (pType == NULL) || (pValue == NULL))
    {
        GWPROV_PRINT("Error input parameter\n");
        return 2;
    }
    while (1)
    {
        ret = CcspBaseIf_discComponentSupportingNamespace
        (
            bus_handle, 
            CR_COMPONENT_ID, 
            pName,
            SUBSYSTEM_PREFIX, 
            &ppComponents, 
            &size
        );  
        if ( ret == CCSP_SUCCESS )
        {
            if ( size != 0 ) 
                break;
                
            GWPROV_PRINT("Can't find destination component for %s\n", pName);
        }
        else
        {
            if((ret == CCSP_MESSAGE_BUS_NOT_EXIST)||(ret == CCSP_CR_ERR_UNSUPPORTED_NAMESPACE))
            {
                GWPROV_PRINT("Can't find destination component for %s FailureCount:%d\n", pName,FailureCount);
            }
            else 
            {
                GWPROV_PRINT("Ccsp msg bus internal error for %s, ret=%d\n", pName, ret);
            }
        }
        FailureCount++;
        if (FailureCount > MAX_DM_OBJ_RETRIES)
        {
            GWPROV_PRINT(" Failed to apply param : %s Tried %d no of times.\n", pName, MAX_DM_OBJ_RETRIES);
            return 2;
        }
        usleep(400*1000);   // 400 msecs
    }
    dst_componentid = ppComponents[0]->componentName;
    dst_pathname    = ppComponents[0]->dbusPath;
    param_val[0].parameterName = (char *)pName;
    param_val[0].parameterValue = (char *)pValue;
    if (!ccsp_type_from_name((char *)pType, &param_val[0].type))
    {
        GWPROV_PRINT("unrecognized type name: %s\n", pName);
        goto freeMem;
    }
    ret = CcspBaseIf_setParameterValues(
          bus_handle,
          dst_componentid,
          dst_pathname,
          0,
          0,
          param_val,
          1,
          TRUE,
          &pFaultParameter);

    if(ret != CCSP_SUCCESS)
    {
        GWPROV_PRINT("Failed to set %s\n", param_val[0].parameterName);
        if (pFaultParameter)
        {
            CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
            bus_info->freefunc(pFaultParameter);
        }
    }
    else
    {
        retVal = 0;
    }
freeMem:
    while( size && ppComponents)
    {
        if (ppComponents[size-1]->remoteCR_dbus_path)
          AnscFreeMemory(ppComponents[size-1]->remoteCR_dbus_path);

        if (ppComponents[size-1]->remoteCR_name)
          AnscFreeMemory(ppComponents[size-1]->remoteCR_name);

        if ( ppComponents[size-1]->componentName )
          AnscFreeMemory( ppComponents[size-1]->componentName );

        if ( ppComponents[size-1]->dbusPath )
          AnscFreeMemory( ppComponents[size-1]->dbusPath );

        AnscFreeMemory(ppComponents[size-1]);
        size--;
    }
    if (ppComponents)
    {
        AnscFreeMemory(ppComponents);
    }
    return retVal;
} 

static int SaveRestartMask(unsigned long mask)
{
    unsigned long restart_mask = RESTART_NONE;
    char restart_module[32] = {0};
    char cmask[12];

    sysevent_get(sysevent_fd_gs, sysevent_token_gs, RESTART_MODULE, restart_module, sizeof(restart_module));
    if ( strlen(restart_module) > 0 )
    {
        restart_mask = strtoul(restart_module, NULL, 10);
    }
    restart_mask |= mask;
    snprintf(cmask, sizeof(cmask), "%u", restart_mask);
    sysevent_set(sysevent_fd_gs, sysevent_token_gs, RESTART_MODULE, cmask, 0);

    return 0;
}

int RestartServicesPerMask(void)
{
    unsigned long restart_mask = RESTART_NONE;
    char restart_module[32] = {0};
    char cmask[12];

    sysevent_get(sysevent_fd_gs, sysevent_token_gs, RESTART_MODULE, restart_module, sizeof(restart_module));
    if ( strlen(restart_module) > 0 )
    {
        restart_mask = strtoul(restart_module, NULL, 10);
    }
    if ( restart_mask != RESTART_NONE )
    {
        if ( restart_mask & RESTART_WIFI )
        {
            system("dmcli eRT setv Device.WiFi.Radio.1.X_CISCO_COM_ApplySetting bool true");
            system("dmcli eRT setv Device.WiFi.Radio.2.X_CISCO_COM_ApplySetting bool true");
        }

        //hotspot-restart internally sets the Device.X_COMCAST-COM_GRE.Tunnel.{i}.Enable parameter, No driver restart is needed after hotspot restart. 
        if ( restart_mask & RESTART_HOTSPOT )
        {
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "hotspot-restart", "", 0);
        }

        snprintf(cmask, sizeof(cmask), "%u", RESTART_NONE);
        sysevent_set(sysevent_fd_gs, sysevent_token_gs, RESTART_MODULE, cmask, 0);
    }

    return 0;
}

void GW_TranslateGWmode2String( int gwmode, char *modestring, size_t len)
{
    char *s;

    switch ( gwmode )
    {
        case DOCESAFE_ENABLE_DISABLE_extIf:
            s = "Bridge mode";
            break;
        case DOCESAFE_ENABLE_IPv4_extIf:
            s = "IPv4-Only mode";
            break;
        case DOCESAFE_ENABLE_IPv6_extIf:
            s = "IPv6-Only mode";
            break;
        case DOCESAFE_ENABLE_IPv4_IPv6_extIf:
            s = "Dual-Stack mode";
            break;
        default:
            s = "Bridge mode";
            break;
    }

    snprintf (modestring, len, "%s", s);
}

static int run_cmd_timeout(const char *caller, char *cmd, char **retBuf, int count)
{
    int fd[2];
    pid_t cpid;

    pipe(fd); /* Create a pipe */

    /* Fork a child to do the work */
    if((cpid = fork()) == -1)
    {
        printf("fork failed\n");
        return -1;
    }

    if(cpid == 0)
    {
        char *token = NULL;
        char *arg_list[MAX_ARGS];
        int i = 0;
        char shell[] = "/bin/sh";
        char shell_arg[] = "-c";

        close(fd[0]); /* Close child input side of pipe */
        dup2(fd[1], 1); /* stdin, stdout, and stderr are 0, 1, and 2, respectively.  redirect child stdout to output side pipe */

        /* Heredoc literals are used in Zigbee/Thread RPC commands.
           So we need to check for that before we tokenize the command */
        if(NULL == strstr(cmd, "<<"))
        {
            /* Tokenize the cmd for arg_list */
            arg_list[MAX_ARGS-1] = NULL;
            token = strtok(cmd, " ");
            for(; ((i < MAX_ARGS) && (token != NULL)); i++)
            {
                arg_list[i] = token;
                token = strtok(NULL, " ");
            }
            if(i < (MAX_ARGS-1))
            {
                arg_list[i++] = NULL;
            }
        }
        else /* heredoc based command */
        {
            arg_list[0] = shell;
            arg_list[1] = shell_arg;
            arg_list[2] = cmd;
            arg_list[3] = NULL;
        }

        if(execvp(arg_list[0], arg_list) < 0) /* execute the command in place */
        {
#ifdef DEBUG
            printf("%s: execvp errno=%s\n", __func__, strerror(errno));
#endif
            printf("Failed to execute command %s\n", cmd);
        }

        fflush(stdout);
        exit(0);
    }
    else
    {
        int flags = fcntl(fd[0], F_GETFL, 0);
        char *ptr = NULL;
        int bytes = 0, total_nbytes = 0;
        *retBuf = NULL; //initialize retBuf
        int status = 0;
        pid_t wait_ret = 0;
        int delay = 50000; // 50ms


        close(fd[1]); /* Close parent output side of pipe */
        fcntl(fd[0], F_SETFL, flags | O_NONBLOCK); /* Set input file descriptor to nonblock */

        /* Let's wait till the child process terminates (with a timeout) */
        while(count > 0)
        {
            wait_ret = waitpid(cpid, &status, WNOHANG);
            if(wait_ret < 0)
            {
                 printf("waitpid() failed\n");
                 break;
            }
            else if(wait_ret > 0)
            {
#ifdef DEBUG
                printf("child status = 0x%x\n", status);
                if(WIFEXITED(status))
                {
                    printf("exited, status=%d\n", WEXITSTATUS(status));
                }
                else if(WIFSIGNALED(status))
                {
                    printf("killed by signal %d\n", WTERMSIG(status));
                }
#endif
                break;
            }

            usleep(delay);
            count--;
        }

#ifdef DEBUG
        printf("waitpid() ret = %d\n", wait_ret);
#endif
        if(wait_ret > 0)
        {
            for(;;)
            {
                if((ptr = realloc(*retBuf, total_nbytes + MAX_LINE_SIZE)) == NULL)
                {
                    printf("%s: realloc %s error\n", caller, cmd);
                    close(fd[0]);
                    //return RC_ERROR;
                    return -1;
                }
                *retBuf = ptr;  /* Update retBuf on realloc */
                ptr += total_nbytes; /* ptr points to current end of string */
                *ptr = 0;

                bytes = read(fd[0], ptr, MAX_LINE_SIZE);
                // handle read error scenario
                if(bytes < 0) { break; }
                // read succeeded - copy bytes into retBuf
                if(bytes > 0)
                {
                    total_nbytes += bytes;
                    ptr = *retBuf + total_nbytes; /* ptr points to current end of string */
                    *ptr = 0;
                }
                // terminating conditions (no more bytes to read)
                if( (bytes < MAX_LINE_SIZE) && (bytes >= 0))
                {
                    close(fd[0]);
#ifdef DEBUG
                    printf("cmd = %s, ptr = %p, len %d, from child: %s\n", cmd, ptr, total_nbytes, *retBuf); fflush(stdout);
#endif
                    //return RC_OK;
                    return 0;
                }
            }
        }
       else
        {
            close(fd[0]);
            kill(cpid, 9); /* Kill child */

            /* Need to wait to avoid zombies */
            wait(&status);

            if(wait_ret == 0)
            {
                //return RC_TIMEOUT;
                return -2;
            }
        }
    }

    //return RC_ERROR;
    return -1;
}

/* Executes a process and store its output in a buffer.
   Buffer needs to be freed by caller. */
static int run_cmd(const char *caller, char *cmd, char **retBuf)
{
    /* Sometimes during the boot up it takes more than 20 sec for a child process to get executed */
    return run_cmd_timeout(caller, cmd, retBuf, 400); // 20 second timeout (400 * 50ms)
}

void *GWP_start_hotspot_threadfunc(void *data)
{
    int timeout = 30;
    char erouter_ipv6[64];

    pthread_detach(pthread_self());

    while(--timeout >= 0)
    {
        erouter_ipv6[0] = 0;
        sysevent_get(sysevent_fd_gs, sysevent_token_gs, "tr_erouter0_dhcpv6_client_v6addr", erouter_ipv6, sizeof(erouter_ipv6));
        if (erouter_ipv6[0] != 0)
        {
            fprintf(stderr,"=========eRouter IPv6 address got: %s=========\n", erouter_ipv6);
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "gre-forceRestart", "1", 0);
            break;
        }
        sleep(1);
    }
    return NULL;
}

void GWP_Update_ErouterMode_by_InitMode(void)
{
    // If Erouter SNMP Init Mode is not set to Honor, then it must take precedence over the init mode in the config file.
    esafeErouterInitModeExtIf_e initMode;

    initMode = DOCESAFE_EROUTER_INIT_MODE_HONOR_ROUTER_INIT_extIf;

    /* Get eRouterSnmpInitMode value from HAL */
    cm_hal_Get_ErouterModeControl(&initMode);
    if (initMode != DOCESAFE_EROUTER_INIT_MODE_HONOR_ROUTER_INIT_extIf)
    {
        translateErouterSnmpInitModeToOperMode(initMode, &eRouterMode);
    }

    GWP_UpdateERouterMode();

    // Set current mode in DOCSIS esafe DB, so SNMP object esafeErouterOperMode reflects current mode.
    eSafeDevice_SetErouterOperationMode(eRouterMode);
}

void translateErouterSnmpInitModeToOperMode(esafeErouterInitModeExtIf_e initMode, DOCSIS_Esafe_Db_extIf_e *operMode)
{
    if (operMode && initMode != DOCESAFE_EROUTER_INIT_MODE_HONOR_ROUTER_INIT_extIf)
    {
        switch(initMode)
        {
            case DOCESAFE_EROUTER_INIT_MODE_DISABLED_extIf:
                *operMode = DOCESAFE_ENABLE_DISABLE_extIf;
                break;
            case DOCESAFE_EROUTER_INIT_MODE_IPV4_extIf:
                *operMode = DOCESAFE_ENABLE_IPv4_extIf;
                break;
            case DOCESAFE_EROUTER_INIT_MODE_IPV6_extIf:
                 *operMode = DOCESAFE_ENABLE_IPv6_extIf;
                 break;
            case DOCESAFE_EROUTER_INIT_MODE_IPV4_IPV6_extIf:
                 *operMode = DOCESAFE_ENABLE_IPv4_IPv6_extIf;
                 break;
            default:
                 break; // Do nothing
        }
    }
}

int GWP_act_ErouterSnmpInitModeSet_callback(void)
{
    esafeErouterInitModeExtIf_e initMode;

    esafeErouterOperModeExtIf_e esafeDbOperMode;

    /* Get the initMode */
    cm_hal_Get_ErouterModeControl(&initMode);
    eSafeDevice_GetErouterOperationMode(&esafeDbOperMode);

    fprintf(stderr, "%s - snmp init mode:%d, eRouterMode:%d, oldRouterMode:%d, SysCfg-LastMode:%d, esafeDbOperMode:%d, cfgFileRouterMode:%d\n",
            __FUNCTION__, (int)initMode, (int)eRouterMode, (int)oldRouterMode, (int)GWP_SysCfgGetInt("last_erouter_mode"), (int)esafeDbOperMode, (int)cfgFileRouterMode);

    DOCSIS_Esafe_Db_extIf_e newErouterMode = eRouterMode;  // Default new mode equal to current mode
    if (initMode != DOCESAFE_EROUTER_INIT_MODE_HONOR_ROUTER_INIT_extIf)
    {
        // Translate SNMP esafe erouter init mode to new erouter oper mode
        translateErouterSnmpInitModeToOperMode(initMode, &newErouterMode);
    }
    else if ( cfgFileRouterMode != -1 )
    {
        // SNMP esafe erouter init mode is set to "Honor", meaning the erouter oper mode
        // must honor the config file TLV202.1 init mode value.
        newErouterMode = cfgFileRouterMode;
    }
    else
    {
        // If TLV202 and WIFI are not configured in the modem bootfile,
        // then the default values as per CUSTOMER ID must be applied.
        // This Case is also applicable for switching from Bridge mode
        newErouterMode = GWP_SysCfgGetInt("default_erouter_mode");;
    }

    if (newErouterMode != eRouterMode)
    {
        // Modem could not reboot automatically when switch between router & full-bridge mode.
        // It's due to sysevent_set "erouter_mode" sometimes is unstable.
        // So call GWP_UpdateERouterMode & reboot directly here to fix the issue.
        oldRouterMode = eRouterMode;
        eRouterMode = newErouterMode;
        fprintf(stderr, "%s - Switching erouter mode from %d to %d, will reboot\n", __FUNCTION__, (int)oldRouterMode, (int)newErouterMode);
        char logbuf[256];
        char oldmode[32];
        char newmode[32];
        GW_TranslateGWmode2String(oldRouterMode, oldmode, sizeof(oldmode));
        GW_TranslateGWmode2String(eRouterMode, newmode, sizeof(newmode));
        snprintf(logbuf, sizeof(logbuf), "Reboot on change of device mode, from %s to %s", oldmode, newmode);
        Send_Release(DHCPV4_PID_FILE);
        Send_Release(DHCPV6_PID_FILE);
        sleep(5);
        // Below event reboot-triggered is to avoid resetting of wireless radios during CM reboot.
        sysevent_set(sysevent_fd_gs, sysevent_token_gs, "reboot-triggered", "1", 0);
        GWP_UpdateERouterMode();

        if (syscfg_set(NULL, "X_RDKCENTRAL-COM_LastRebootReason", "Erouter Mode Change") != 0)
        {
            GWPROV_PRINT(("RDKB_REBOOT : RebootDevice syscfg_set failed erouter mode change\n"));
        }

        if (syscfg_set_commit(NULL, "X_RDKCENTRAL-COM_LastRebootCounter", "1") != 0)
        {
            GWPROV_PRINT(("syscfg_set failed\n"));
        }

        sleep(10);
        system("reboot"); // Reboot on change of device mode.
    }

    return 0;
}

/* 
 * Add handling of Vendor specific TLV 202.43.12 - Data Model Object
 */
/**************************************************************************/
/*! \fn const char *GW_MapTr69TypeToDmcliType(const char *tr69Type)
 **************************************************************************
 *  \brief Map a TR-069 type (string) to a dmcli type (string)
 *  \param[in] tr69Type
 *  \return const char *
 **************************************************************************/
static const char *GW_MapTr69TypeToDmcliType(const char *tr69Type)
{
    struct TypeMap
    {
        const char *tr69Type;
        const char *dmcliType;
    };

    const struct TypeMap typeMap[] =
    {
        /* TR069 type,    dmcli Type */
        { "string",      "string"     },
        { "int",         "int"        },
        { "unsignedInt", "uint"       },
        { "boolean",     "bool"       },
        { "dateTime",    "dateTime"   },
        { "base64",      "base64"     },
        { NULL,           NULL        }  // This entry must be last!
    };

    if (tr69Type != NULL)
    {
        int i = 0;
        while (typeMap[i].tr69Type != NULL)
        {
            if (strcmp(tr69Type, typeMap[i].tr69Type) == 0)
            {
                return typeMap[i].dmcliType;
            }
            i++;
        }
    }
    return NULL;
}

/*
 * Add handling of Vendor specific TLV 202.43.12 - Data Model Object
 */
/**************************************************************************/
/*! \fn int mapIndex(int i, int index)
 **************************************************************************
 *  \brief Map a TR-069 index to a dmcli index
 *  \param[in] tr69Index - index and i - type of data model
 *  \return int
 **************************************************************************/

static int mapIndex (int i, int index)
{
	int ret = -1;

	switch (i)
	{
		case 0:
		case 1:
			/*Device.WiFi.SSID. and Device.WiFi.AccessPoint.
			  10001~10008 maps to 1,3,5,7,9,11,13,15
			  10101~10108 maps to 2,4,6,8,10,12,14,16*/
			if(index >= (RADIO_1_TR069_INDEX + 1) && index <= (RADIO_1_TR069_INDEX + 8))
				ret = ((index - RADIO_1_TR069_INDEX) * 2 -1);
			else if(index >= (RADIO_2_TR069_INDEX + 1) && index <= (RADIO_2_TR069_INDEX + 8))
				ret = ((index - RADIO_2_TR069_INDEX)*2);
			break;
		case 2:
		case 3:
			/*Device.WiFi.Radio. and Device.WiFi.X_LGI-COM_ATM.Radio.
			  10000 - 1
			  10100 - 2*/
			if(index == RADIO_1_TR069_INDEX)
				ret = RADIO_1_CCSP_INDEX;
			else if(index == RADIO_2_TR069_INDEX)
				ret = RADIO_2_CCSP_INDEX;
			break;
		case 4:
			/*Device.WiFi.X_LGI-COM_ATM.Radio.1.SSID.
			  10001~10008 maps to 1,2,3,4,5,6,7,8*/
			if(index >= (RADIO_1_TR069_INDEX + 1) && index <= (RADIO_1_TR069_INDEX + 8))
				ret = (index - RADIO_1_TR069_INDEX);
			break;
		case 5:
			/*Device.WiFi.X_LGI-COM_ATM.Radio.2.SSID.
			  10101~10108 maps to 1,2,3,4,5,6,7,8*/
			if(index >= (RADIO_2_TR069_INDEX + 1) && index <= (RADIO_2_TR069_INDEX + 8))
				ret = (index - RADIO_2_TR069_INDEX);
			break;
		default:
			break;
	}

	return ret;
}

/*
 * Add handling of Vendor specific TLV 202.43.12 - Data Model Object
 */
/**************************************************************************/
/*! \fn int GW_MapTr69IndexToDmcliIndex(const char *tr69Name, char *dmcliName)
 **************************************************************************
 *  \brief Map a parameter name with TR-069 index to a parameter name with dmcli index
 *  \param[in] data model paramters name with tr69Index and place holder for return Name dmcliName
 *  \return int
 **************************************************************************/

static int GW_MapTr69IndexToDmcliIndex(const char *tr69Name, char *dmcliName)
{
	char indexMap[NUMBER_OF_DATA_MODELS][MAX_DATAMODEL_SIZE] = {WIFI_SSID, WIFI_ACCESSPOINT, WIFI_RADIO, WIFI_ATM, WIFI_ATM_SSID_RADIO1, WIFI_ATM_SSID_RADIO2};
	char recName[MAX_DATAMODEL_SIZE];
	int index= 0;
	int newIndex= 0;
	int i= 0;
	char restDmlString[MAX_DATAMODEL_SIZE];
	int ret = 0;
	bool atm_ssid_set = false;

	strcpy(recName,tr69Name);

	for(i = 0; i < NUMBER_OF_DATA_MODELS; i++)
	{
		if (strncmp(recName, indexMap[i], strlen(indexMap[i])) == 0)
		{
			sscanf(&recName[strlen(indexMap[i])],"%d%s",&index,restDmlString);

			if(index == 0)
				break;

			newIndex = mapIndex(i,index);

			if(newIndex == -1)
			{
				ret = -1;
				break;
			}

			sprintf(dmcliName,"%s%d%s",indexMap[i],newIndex,restDmlString);

			if(!atm_ssid_set && ((strncmp(dmcliName, WIFI_ATM_SSID_RADIO1, strlen(WIFI_ATM_SSID_RADIO1)) == 0) ||
			(strncmp(dmcliName, WIFI_ATM_SSID_RADIO2, strlen(WIFI_ATM_SSID_RADIO2)) == 0)))
			{
				strcpy(recName,dmcliName);
				atm_ssid_set = true;
			}
			else
			{
				break;
			}
		}
	}
	return ret;
}

/**************************************************************************/
/*! \fn bool GW_SetParam(char *pName, char *pType, char *pValue);
 **************************************************************************
 *  \brief Set DataModel parameter
 *  \param[in] pName - Parameter Name
 *  \param[in] pType - Parameter Type (dmcli type string)
 *  \param[in] pValue - Parameter Value
 *  \return true - Parameter was found and set, false - Parameter not found
 **************************************************************************/
static bool GW_SetParam(void* bus_handle, const char *pName, const char *pType, const char *pValue)
{
    char cmd[1024];
    bool success = false;
    char retName[MAX_DATAMODEL_SIZE] = "";
    int ret = 0;

    if (!bus_handle || pName == NULL || pType == NULL || pValue == NULL)
    {
        return false;
    }

    /* Skip WiFi Apply TLV */
    if ( strstr(pName, DEVICE_WIFI) != NULL && strstr(pName, DEVICE_WIFI_APPLY) != NULL )
    {
        return true;
    }

    if((strncmp(pName, DEVICE_WIFI, strlen(DEVICE_WIFI)) == 0))
    {
        ret = GW_MapTr69IndexToDmcliIndex(pName,retName);
        if(ret == -1)
            return true;
    }

    if(strlen(retName) != 0)
        ret = GW_SetParameterValue (bus_handle, retName, pType, pValue);
    else
        ret = GW_SetParameterValue (bus_handle, pName, pType, pValue);
    if (ret <= 1) success=true; 

    /* keep a flag if we ever set a WiFi param so we can apply settings later */
    if (success)
    {
        unsigned long restart_mask = RESTART_NONE;
        if ( strncmp(pName, DEVICE_HOTSPOT, sizeof(DEVICE_HOTSPOT)-1) == 0 )
        {
             restart_mask |= RESTART_HOTSPOT;
        }
        else if ( strncmp(pName, DEVICE_WIFI, sizeof(DEVICE_WIFI)-1) == 0 )
        {
            restart_mask |= RESTART_WIFI;
        }
        SaveRestartMask(restart_mask);
    }

    return success;
}

/**************************************************************************/
/*! \fn void GW_DmObjectListAdd(DmObject_t *pDmObj);
 **************************************************************************
 *  \brief Add DataModel parameter to a list for retrying later
 *  \param[in] pDmObj - Parameter to add (must be copied)
 *  \return none
 **************************************************************************/
static void GW_DmObjectListAdd(DmObject_t *pDmObj)
{
    /* make a copy of the object to store */
    DmObject_t *pNewDmObj = malloc(sizeof(DmObject_t));
    if (pNewDmObj != NULL)
    {
        memcpy(pNewDmObj, pDmObj, sizeof(DmObject_t));
        if (gpDmObjectHead == NULL)
        {
            gpDmObjectHead = pNewDmObj;
        }
        else
        {
            /* add it to the end to preserve the order */
            DmObject_t *pCurr = gpDmObjectHead;
            while (pCurr->pNext != NULL)
            {
                pCurr = pCurr->pNext;
            }
            pCurr->pNext = pNewDmObj;
        }
        pNewDmObj->pNext = NULL;
    }
}

/**************************************************************************/
/*! \fn void GW_DmObjectAddToAliasList(DmObject_t *pDmObj);
 **************************************************************************
 *  \brief Add DataModel parameter with alias to a sorted list
 *  \param[in] pDmObj - Parameter to add (must be copied)
 *  \return none
 **************************************************************************/
static void GW_DmObjectAddToAliasList(DmObject_t *pDmObj)
{
    /* make a copy of the object to store */
    DmObject_t *pNewDmObj = malloc(sizeof(DmObject_t));
    /* Pointers for list traverse */
    DmObject_t *pPrev = NULL;
    DmObject_t *pCurr = gpDmObjectHeadAlias;

    /* Parse parent object and alias,
     * which will be added to the list in sorted order
     */
    char *object_name = strdup(pDmObj->Name);
    char *pParent = strtok(object_name, "[");
    char *pAlias = strtok(NULL, "]");
    bool matchFound = false;

    if (pNewDmObj != NULL)
    {
        memcpy(pNewDmObj, pDmObj, sizeof(DmObject_t));
        if (gpDmObjectHeadAlias == NULL)
        {
            gpDmObjectHeadAlias = pNewDmObj;
        }
        else
        {
            /* Add the new node in sorted order based on Parent object
             * and alias for the instance number
             */
            while (pCurr)
            {
                if (isParentMatch(pCurr->Name, pParent))
                {
                    break;
                }
                pPrev = pCurr;
                pCurr = pCurr->pNext;
            }
            while (pCurr)
            {
                if (!isParentMatch(pCurr->Name, pParent))
                {
                    break;
                }
                if (isAliasMatch(pCurr->Name, pParent, pAlias))
                {
                    matchFound = true;
                }
                else
                {
                    if (matchFound)
                        break;
                }
                pPrev = pCurr;
                pCurr = pCurr->pNext;
            }
            pNewDmObj->pNext = pCurr;
            pPrev->pNext = pNewDmObj;
        }
    }
    else
    {
        GWPROV_PRINT("Failed to allocate memory for data model object: %s \n", pDmObj->Name);
    }
    free(object_name);
}

/**************************************************************************/
/*! \fn bool GW_DmObjectListIsEmpty(void);
 **************************************************************************
 *  \brief Determines if DataModel list is empty
 *  \return bool - true if the list is empty
 **************************************************************************/
static bool GW_DmObjectListIsEmpty(void)
{
    return (gpDmObjectHead == NULL && gpDmObjectHeadAlias == NULL);
}

/**************************************************************************/
/*! \fn void GW_DmObjectListApply(void);
 **************************************************************************
 *  \brief Runs through the data model list and attempts to set anything
 *         in the list. Removes the param from the list if successful or
 *         max retries exceeded.
 *  \return none
 **************************************************************************/
static void GW_DmObjectListApply(void)
{
    bool success = false;
    DmObject_t *pPrev = NULL;
    DmObject_t *pCurr = gpDmObjectHead;

    if (!init_message_bus())
    {
        return;
    }

    /* Call GW_HandleAliasDmList(), to process gpDmObjectHeadAlias list */
    GW_HandleAliasDmList(bus_handle);
#if 0
    while (pCurr != NULL)
    {
        /* GW_SetParam() only returns failure if the parameter could not be found... it can still fail
        for invalid value, etc., but in those cases we don't want to retry because there is no point */
        success = GW_SetParam(bus_handle, pCurr->Name, GW_MapTr69TypeToDmcliType(pCurr->Type), pCurr->Value);

        if (!success)
        {
            pCurr->FailureCount++;
        }
        /* remove it from the list on success or when we've exhausted our retries */
        if (success || pCurr->FailureCount > MAX_DM_OBJ_RETRIES)
        {
            if (pCurr == gpDmObjectHead)
            {
                gpDmObjectHead = pCurr->pNext;
            }
            else
            {
                pPrev->pNext = pCurr->pNext;
            }

            if(pCurr->FailureCount > MAX_DM_OBJ_RETRIES) {
                GWPROV_PRINT(" Failed to apply param : %s Tried %d no of times.\n", pCurr->Name, MAX_DM_OBJ_RETRIES);
            }

            /* free the node */
            DmObject_t *pOld = pCurr;
            pCurr = pCurr->pNext;
            free(pOld);
        }
        else
        {
            pPrev = pCurr;
            pCurr = pCurr->pNext;
        }
    }
#else
    while (pCurr != NULL)
    {
        GW_SetParam(bus_handle, pCurr->Name, GW_MapTr69TypeToDmcliType(pCurr->Type), pCurr->Value);

        if (pCurr == gpDmObjectHead)
        {
            gpDmObjectHead = pCurr->pNext;
        }
        else
        {
            pPrev->pNext = pCurr->pNext;
        }

        /* free the node */
        DmObject_t *pOld = pCurr;
        pCurr = pCurr->pNext;
        free(pOld);
    }
#endif

}

/**************************************************************************/
/*! \fn void GW_DmObjectApplyWiFiSettings(void);
 **************************************************************************
 *  \brief Applies WiFi Settings using the DataModel
 *  \return none
 **************************************************************************/
#if 0
static void GW_DmObjectApplyWiFiSettings(void)
{
    GW_SetParam("Device.WiFi.Radio.1.X_CISCO_COM_ApplySettingSSID", "int", "1");
    GW_SetParam("Device.WiFi.Radio.1.X_CISCO_COM_ApplySetting", "bool", "true");
    GW_SetParam("Device.WiFi.Radio.2.X_CISCO_COM_ApplySettingSSID", "int", "2");
    GW_SetParam("Device.WiFi.Radio.2.X_CISCO_COM_ApplySetting", "bool", "true");
}
#endif

/**************************************************************************/
/*! \fn char* last_occurrence(char *haystack, char *needle);
 **************************************************************************
 *  \brief Find the last occurrence of needle
 *  \return last occurrence of needle. If not found null
 **************************************************************************/
static char* last_occurrence(char *haystack, char *needle)
{
    char *ptr, *last = NULL;
    ptr = haystack;
    while((ptr = strstr(ptr, needle)) != NULL )
    {
        last = ptr;
        ptr++;
    }
    return last;
}


/**************************************************************************/
/*! \fn long find_instance(char *output, char *parent);
 **************************************************************************
 *  \brief Find The Instance Number
 *  \return long Instance Number
 **************************************************************************/
static long find_instance(char *output, char *parent)
{
    long instance = 0;
    char *p;
    p = last_occurrence(output,parent);
    if(p != NULL)
    {
        int size_of_parent = strlen(parent);
        p += size_of_parent;
        while(*p)
        {
            if(isdigit(*p))
            {
                instance = strtol(p,&p,10);
                return instance;
            }
            else
            {
                p++;
            }
       }
    }
    return instance;
}
/**************************************************************************/
/*! \fn char check_alias(char * cmd_output, char * alias)
 **************************************************************************
 *  \brief Get the value from the output and check with the alias
 *  \return bool success
 **************************************************************************/
static bool check_alias(char * cmd_output, char * alias)
{
    bool success = false;
    char *tmp = NULL;

    if(cmd_output && alias)
    {
        tmp = strstr(cmd_output, "value:");
        if(tmp)
        {
            char *p;

            if (sscanf(tmp, "value: %m[^ \n]\n", &p) == 1)
            {
                if(strcmp(p,alias) == 0)
                {
                    success = true;
                }
                free(p);
                p = NULL;
            }
        }
    }
    return success;
}

static void GW_HandleAliasDmList(void* bus_handle)
{
    componentStruct_t **ppComponents = NULL;
    DmObject_t *pLastNode = NULL;
    DmObject_t *pCurr = gpDmObjectHeadAlias;
    DmObject_t *pCrawl;
    DmObject_t *pPrev;
    char *dst_componentid = NULL;
    char *dst_pathname = NULL;
    char cmd[1024];
    char output[1024];
    int size2 = 0;
    int idx = -1;
    bool success = false;

    if (!bus_handle)
    {
        return;
    }
    while (pCurr != NULL)    /* Outer Loop: runs once for each parent Object */
    {
        char *object_name = strdup(pCurr->Name);
        char *objParent = strtok(object_name, "[");
        char *cObj, *parent, *alias, *parameterName;

        int ret = CcspBaseIf_discComponentSupportingNamespace(bus_handle, CR_COMPONENT_ID, objParent, SUBSYSTEM_PREFIX, &ppComponents, &size2);
        if (ret != CCSP_SUCCESS || size2 == 0)
        {
            GWPROV_PRINT("can't find destination component for %s\n", objParent);
            pCrawl = pCurr;
            while (pCrawl)    /* Remove all the parameters of same parent Object from current list, will be retried in next iteration */
            {
                if (!isParentMatch(pCrawl->Name, objParent))
                {
                    break;
                }
                pCrawl->FailureCount++;
                if (pCrawl->FailureCount > MAX_DM_OBJ_RETRIES)
                {
                    GWPROV_PRINT("Discarding after max retries %s\n", pCrawl->Name);
                    DmObject_t *pNext = pCrawl->pNext;
                    free(pCrawl);
                    pCrawl = pNext;

                    if (!pLastNode)
                    {
                        gpDmObjectHeadAlias = pCrawl;
                    }
                    else
                    {
                        pLastNode->pNext = pCrawl;
                    }
                }
                else {
                    pLastNode = pCrawl;
                    pCrawl = pCrawl->pNext;
                }
            }
            pCurr = pCrawl;
            free(object_name);
            continue;
        }
        dst_componentid = ppComponents[0]->componentName;
        dst_pathname    = ppComponents[0]->dbusPath;

	/* Get all existing alias for current object */
        snprintf(cmd, sizeof(cmd), "dmcli eRT true getvalues %s | grep Alias -A1", objParent);

        FILE *fp = popen(cmd, "r");
        while (fgets(output, sizeof(output), fp) != NULL)
        {
            if (strstr(output, objParent))
            {
                idx = getIndex(output, objParent);
                if (idx == -1)
                {
                    GWPROV_PRINT("No valid index found %s\n", output);
                }
            }
            else if (strstr(output, "value: ") && idx != -1)
            {
                bool matchFound = false;
                char *pAliasName = strstr(output, "value:") + strlen("value:");
                while (*pAliasName == ' ')    //trim leading whitespaces
                    pAliasName++;
                char *ptr = pAliasName;
                while (*ptr != '\n' && *ptr != '\0')    //trim trailing whitespaces
                    ptr++;
                *ptr = '\0';
                ptr--;
                if(*ptr == ' ')
                    *ptr = '\0';

                pCrawl = NULL;
                pPrev = NULL;

                GWPROV_PRINT("Using idx %d for %s[%s]\n", idx, objParent, pAliasName);
                while (pCurr)
                {
                    DmObject_t *pNext = pCurr->pNext;
                    cObj = strdup(pCurr->Name);
                    parent = strtok(cObj, "[");
                    alias = strtok(NULL, "]");
                    parameterName = strtok(NULL,"].");

                    if (strcmp(parent, objParent))
                    {
                        free(cObj);
                        break;
                    }
                    else
                    {
                        if (strcmp(pAliasName, alias) == 0)
                        {
                            char *remaining = strtok(NULL, "");
                            if (remaining)
                            {
                                /*
                                    If it is a nested Alias object, resolve the first alias and
                                    add it to gpDmObjectHeadAlias for further processing.
                                */
                                if (strstr(remaining, "["))
                                {
                                    DmObject_t nestedAliasObject;
                                    memset(&nestedAliasObject, 0, sizeof(DmObject_t));
                                    sprintf(nestedAliasObject.Name, "%s%d.%s.%s",parent, idx, parameterName, remaining);
                                    strcpy(nestedAliasObject.Value, pCurr->Value);
                                    strcpy(nestedAliasObject.Type, pCurr->Type);
                                    nestedAliasObject.IsAliasBased = true;
                                    GWPROV_PRINT("Nested [Alias] TLV202.43 object full name : %s\n", nestedAliasObject.Name);
                                    GW_DmObjectAddToAliasList(&nestedAliasObject);
                                    if(pNext == NULL)
                                    {
                                        pNext = pCurr->pNext;
                                    }
                                }
                            }
                            else
                            {
                                matchFound = true;
                                snprintf(cmd, sizeof(cmd), "%s%d.%s", parent, idx, parameterName);
                                int relMem = 0;
                                char *internalName = aliasGetInternalName(cmd, &relMem);
                                if (internalName)
                                {
                                    GWPROV_PRINT("gw-prov-app: replacing TLV202.43.12 parameter %s with internal name %s\n", cmd, internalName);
                                    snprintf(cmd, sizeof(cmd), "%s", internalName);
                                    if (relMem)
                                        AnscFreeMemory(internalName);
                                }
                                GW_SetParam(bus_handle, cmd, GW_MapTr69TypeToDmcliType(pCurr->Type), pCurr->Value);
                            }

                            free(pCurr);
                            free(cObj);
                        }
                        else
                        {
                            free(cObj);
                            if (matchFound)
                                break;

                            if (!pPrev)
                                pCrawl = pCurr;
                            else
                                pPrev->pNext = pCurr;
                            pPrev = pCurr;
                        }
                        pCurr = pNext;
                    }
                }
                if (pPrev)
                {
                    pPrev->pNext = pCurr;
                    pCurr = pCrawl;
                }
            }
        }
        pclose(fp);

        /* Create new table for entries which are not available in existing list */
        char *lastAlias = NULL;
        while (pCurr)
        {
            DmObject_t *pNext = pCurr->pNext;
            cObj = strdup(pCurr->Name);
            parent = strtok(cObj, "[");

            if (strcmp(parent, objParent) != 0)
            {
                free(cObj);
                break;
            }

            alias = strtok(NULL, "]");
            parameterName = strtok(NULL,"].");

            if (!lastAlias || strcmp(lastAlias, alias) != 0)    /* Create object only once for each alias/instance number */
            {
                if (lastAlias) {
                    free(lastAlias);
                    lastAlias = NULL;
                }

                ret = CcspBaseIf_AddTblRow(bus_handle, dst_componentid, dst_pathname, 0, parent, &idx);
                if (ret == CCSP_SUCCESS)
                {
                    GWPROV_PRINT("Added idx %d for %s[%s]\n", idx, objParent, alias);
                    snprintf(cmd, sizeof(cmd), "%s%d.Alias", parent, idx);
                    GW_SetParam(bus_handle, cmd, "string", alias);
                    lastAlias = strdup(alias);
                }
                else
                {
                    GWPROV_PRINT("Unable to create object %s, ret=%d\n", parent, ret);
                }
            }

            if (ret == CCSP_SUCCESS)
            {
                snprintf(cmd, sizeof(cmd), "%s%d.%s", parent, idx, parameterName);
                int relMem = 0;
                char *internalName = aliasGetInternalName(cmd, &relMem);
                if (internalName)
                {
                    GWPROV_PRINT("gw-prov-app: replacing TLV202.43.12 parameter %s with internal name %s\n", cmd, internalName);
                    snprintf(cmd, sizeof(cmd), "%s", internalName);
                    if (relMem)
                        AnscFreeMemory(internalName);
                }
                GW_SetParam(bus_handle, cmd, GW_MapTr69TypeToDmcliType(pCurr->Type), pCurr->Value);
            }

            free(pCurr);
            free(cObj);
            pCurr = pNext;
        }
        if (!pLastNode)
        {
            gpDmObjectHeadAlias = pCurr;
        }
        else
        {
            pLastNode->pNext = pCurr;
        }

        while( size2 && ppComponents)
        {
            if (ppComponents[size2-1]->remoteCR_dbus_path)
                AnscFreeMemory(ppComponents[size2-1]->remoteCR_dbus_path);

            if (ppComponents[size2-1]->remoteCR_name)
                AnscFreeMemory(ppComponents[size2-1]->remoteCR_name);

            if ( ppComponents[size2-1]->componentName )
                AnscFreeMemory( ppComponents[size2-1]->componentName );

            if ( ppComponents[size2-1]->dbusPath )
                AnscFreeMemory( ppComponents[size2-1]->dbusPath );

            AnscFreeMemory(ppComponents[size2-1]);

            size2--;
        }
        if (ppComponents)
        {
            AnscFreeMemory(ppComponents);
        }
        free(object_name);
    }
}

#if 0

/**************************************************************************/
/*! \fn bool GW_HandleAliasDm(void* bus_handle, DmObject_t dmObject, int objectListAddNeeded)
 **************************************************************************
 *  \brief Handle [Alias] format TLV202.43.12 objects
 *  \param[in] dmObject - Parameter which has the info about TLV202.43.12 object
 *  \param[in] objectListAddNeeded - Indicates whether dmObject needs to be
 *             added in list in case of failure
 *  \return bool - true if dmObject successfully applied.
 **************************************************************************/
static bool GW_HandleAliasDm(void* bus_handle, DmObject_t dmObject, int objectListAddNeeded)
{
    char *parent, *alias, *parameterName;
    char *cmd_output = NULL;
    int flag = 0;
    long inst = -1;
    char cmd[1024];
    int  i;
    bool return_value = false;
    char *object_name;
    char *comp_not_found_err = "Can't find destination component";
    char *execution_fail_err = "Execution fail";

    if (!bus_handle)
    {
        return false;
    }
    object_name = strdup(dmObject.Name);
    if(object_name == NULL)
    {
        GWPROV_PRINT("strdup failed in %s\n",__func__);
        goto out;
    }

    parent = strtok(object_name, "[");
    alias = strtok(NULL, "]");
    parameterName = strtok(NULL,"].");

    if((parent == NULL) || (alias == NULL) || (parameterName == NULL))
    {
        GWPROV_PRINT("Invalid format for [Alias] based TLV202.43.12: '%s'\n",dmObject.Name);
        free(object_name);
        return return_value;
    }

    snprintf(cmd, sizeof(cmd), "dmcli eRT getnames %s",parent);

    run_cmd(__func__,cmd, &cmd_output);

    if(cmd_output == NULL)
    {
        goto out;
    }

    /* If dmcli returns "Can't find destination component" error
       that means ccsp components are not online yet. So add it
       to the list for retry */
    if(strstr(cmd_output, comp_not_found_err))
    {
        GWPROV_PRINT("ccsp components are not up yet...\n");
        free(cmd_output);
        goto out;
    }

    /* If dmcli returns "Execution fail" error then no need to add it to the list for retrying */
    if(strstr(cmd_output, execution_fail_err))
    {
        GWPROV_PRINT("Execution failed : %s\n", cmd);
        free(object_name);
        free(cmd_output);
        return return_value;
    }

    inst = find_instance(cmd_output, parent);

    free(cmd_output);
    cmd_output = NULL;

    for(i = 1; i <= inst; i++)
    {
        snprintf(cmd, sizeof(cmd), "dmcli eRT getvalues %s%d.Alias",parent,i);
        run_cmd(__func__,cmd, &cmd_output);

        if(cmd_output != NULL)
        {
            bool isalias = check_alias(cmd_output, alias);

            free(cmd_output);
            cmd_output = NULL;

            if(isalias)
            {
                flag = 1;
                snprintf(cmd, sizeof(cmd), "%s%d.%s", parent, i, parameterName);
                if(GW_SetParam(bus_handle, cmd,dmObject.Type,dmObject.Value))
                {
                    /* return true only if the final object set is successful */
                    return_value = true;
                }
                break;
            }
        }
    }

    if(!flag)
    {
        snprintf(cmd, sizeof(cmd), "dmcli eRT addtable %s ", parent);
        run_cmd(__func__,cmd, &cmd_output);

        if(cmd_output != NULL)
        {
            inst = find_instance(cmd_output, parent);
            free(cmd_output);
            cmd_output = NULL;

            snprintf(cmd, sizeof(cmd), "%s%d.Alias", parent, inst);
            if(GW_SetParam(bus_handle, cmd,"string", alias))
            {
                snprintf(cmd, sizeof(cmd), "%s%d.%s", parent, inst, parameterName);
                if(GW_SetParam(bus_handle, cmd,dmObject.Type,dmObject.Value ))
                {
                    /* return true only if the final object set is successful */
                    return_value = true;
                }
            }
        }
    }

out:
    if(objectListAddNeeded)
    {
        GW_DmObjectAddToAliasList(&dmObject);
    }
    free(object_name);

    return return_value;
}
#endif
/**************************************************************************/
/*! \fn bool GW_DmObjectThread(void *pParam);
 **************************************************************************
 *  \brief Worker thread to process VendorSpecific Sub TLVs (TLV202.43.x)
 *  \param[in] pParam - unused
 *  \return void * - unused
 **************************************************************************/
static void *GW_DmObjectThread(void *pParam)
{
    int alias_mapper_enabled = 1;
    char *internalName;

    /* copy to local buffer so we can manipulate it */
    char tlvData[GW_SUBTLV_VENDOR_SPECIFIC_DATAMODEL_OBJECT_MAX_LEN + 1];

    while (1)
    {
        size_t bytesRead = 0;
        fd_set readset;

        FD_ZERO(&readset);
        FD_SET(DmObjectSockFds[0], &readset);

        /* if the queued DmObject list is empty, just wait forever on the socket for something
           to process; otherwise, timeout after 1 second so we can retry processing the list  */
        struct timeval tval;
        struct timeval *pTval = NULL;
        if (!GW_DmObjectListIsEmpty() && gbDmObjectParseCfgDone)
        {
            tval.tv_sec = 1;
            tval.tv_usec = 0;
            pTval = &tval;
        }
        select(DmObjectSockFds[0]+1, &readset, NULL, NULL, pTval);

        /* if there is something to read, read it! */
        bytesRead = 0;
        if (FD_ISSET(DmObjectSockFds[0], &readset))
        {
            bytesRead = read(DmObjectSockFds[0], tlvData, GW_SUBTLV_VENDOR_SPECIFIC_DATAMODEL_OBJECT_MAX_LEN);
        }

        /* if there is something to process, process it! */
        if (bytesRead > 0)
        {
            tlvData[bytesRead] = '\0';

            /* if this is a token telling us the config parsing is done,
               just set the config done flag */
            if (!strcmp(tlvData, TLV2024312_CONFIG_DONE))
            {
#if DEBUG
                GWPROV_PRINT("Objects in the list: \n");
                DmObject_t *pCrawl = gpDmObjectHead;
                while (pCrawl) {
                    GWPROV_PRINT("%s\n", pCrawl->Name);
                    pCrawl = pCrawl->pNext;
                }

                pCrawl = gpDmObjectHeadAlias;
                while (pCrawl)
                {
                    GWPROV_PRINT("%s\n", pCrawl->Name);
                    pCrawl = pCrawl->pNext;
                }
#endif
                gbDmObjectParseCfgDone = true;
            }
            else
            {
                DmObject_t dmObject;
                memset(&dmObject, 0, sizeof(DmObject_t));

                /* parse the sub-strings */
                char *pDelim = "|";
                char *pStr = tlvData;

                /* first token is the parameter name */
                char *pToken = strtok_r(pStr, pDelim, &pStr);
                if (pToken != NULL)
                {
                    strncpy(dmObject.Name, pToken, sizeof(dmObject.Name)-1);
                }

                /* second token is the parameter type */
                pToken = strtok_r(NULL, pDelim, &pStr);
                if (pToken != NULL)
                {
                    strncpy(dmObject.Type, pToken, sizeof(dmObject.Type)-1);
                }

                /* third token is the parameter value */
                pToken = strtok_r(NULL, pDelim, &pStr);
                if (pToken != NULL)
                {
                    strncpy(dmObject.Value, pToken, sizeof(dmObject.Value)-1);
                }

                if ((dmObject.Name[0] == '\0') || (dmObject.Type[0] == '\0') || (dmObject.Value[0] == '\0'))
                {
                    fprintf(stderr, "Invalid format for TLV202.43.12: '%s'\n", tlvData);
                    continue;
                }

                if (alias_mapper_enabled)
                {
                    int relMem = 0;
                    internalName = aliasGetInternalName(dmObject.Name, &relMem);
                    if (internalName)
                    {
                        printf("gw-prov-app: replacing TLV202.43.12 parameter %s with internal name %s\n", dmObject.Name, internalName);
                        strncpy(dmObject.Name, internalName, sizeof(dmObject.Name) - 1);
                        dmObject.Name[sizeof(dmObject.Name)-1] = '\0';
                        if (relMem)
                            AnscFreeMemory(internalName);
                    }
                }

                /* convert TR069 type to dmcli type */
                const char *pTypeDmcli = GW_MapTr69TypeToDmcliType(dmObject.Type);
                if (pTypeDmcli == NULL)
                {
                    fprintf(stderr, "Invalid type field for TLV202.43.12: '%s'\n", tlvData);
                    continue;
                }

                dmObject.IsAliasBased = false;
                if(strstr(dmObject.Name,"["))
                {
                    GWPROV_PRINT("Processing a [Alias] based TLV202.43 object : %s \n", dmObject.Name);
                    dmObject.IsAliasBased = true;
                    GW_DmObjectAddToAliasList(&dmObject);
                }
                else {
                    GWPROV_PRINT("Processing a TLV202.43 object : %s \n", dmObject.Name);
                    GW_DmObjectListAdd(&dmObject);
                }
            }
        }

        /* if there was no new TLV to process, try to handle our queued list */
        /* Since majority of the datamodel parameters are in PandM module,
         * Added wait for PandM to be initialized before trying to set the parameters.
         */
        if (!GW_DmObjectListIsEmpty() && access("/tmp/pam_initialized", F_OK) == 0)
        {
            GW_DmObjectListApply();
        }

        /* if config processing is done, AND our queued list is empty, AND we set some WiFi thing,
           then go ahead and apply those WiFi setting (yet another WiFi restart, yeehaw) */
        if (gbDmObjectParseCfgDone && GW_DmObjectListIsEmpty())
        {
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "cfgfile_status", "End", 0);
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "cfgfile_apply", "", 0);
            system("touch /tmp/cfg_file_applied");
            gbDmObjectParseCfgDone = false;
        }
    }


    return NULL;
}

/**************************************************************************/
/*! \fn TlvParseCallbackStatusExtIf_e GW_VendorSpecificSubTLVParse(unsigned char type, unsigned short length, const unsigned char* value);
 **************************************************************************
 *  \brief Process VendorSpecific Sub TLVs (TLV202.43.x)
 *  \param[in] type
 *  \param[in] length
 *  \param[in] value
 *  \return 0
 **************************************************************************/
TlvParseCallbackStatusExtIf_e GW_VendorSpecificSubTLVParse(unsigned char type, unsigned short length, const unsigned char* value)
{
    static bool bDmObjectThreadStarted = false;

    if (type != GW_SUBTLV_VENDOR_SPECIFIC_DATAMODEL_OBJECT)
    {
        fprintf(stderr, "Unrecognized TLV202.43 SubTLV: Type=%u\n", type);
        return TLV_PARSE_CALLBACK_ABORT_EXTIF;
    }
    if ((value == NULL) || (length > GW_SUBTLV_VENDOR_SPECIFIC_DATAMODEL_OBJECT_MAX_LEN))
    {
        fprintf(stderr, "Illegal TLV202.43.12: '%s'\n", value ? (char *)value : "null");
        return TLV_PARSE_CALLBACK_ABORT_EXTIF;
    }
    /* start the worker thread to handle these sets asynchronously (if not already started) */
    if (!bDmObjectThreadStarted)
    {
        /* create a unix socket pair to communicate with the worker thread */
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, DmObjectSockFds))
        {
            return TLV_PARSE_CALLBACK_ABORT_EXTIF;
        }

        /* launch the thread */
        pthread_t dmObjectThread;
        if (pthread_create(&dmObjectThread, NULL, GW_DmObjectThread, NULL))
        {
            close(DmObjectSockFds[0]);
            close(DmObjectSockFds[1]);
            return TLV_PARSE_CALLBACK_ABORT_EXTIF;
        }
        bDmObjectThreadStarted = true;
    }

    /* send the TLV data to the worker thread */
    write(DmObjectSockFds[1], value, length);
    return TLV_PARSE_CALLBACK_OK_EXTIF;
}

static void Send_Release(char *file_name)
{
    FILE *fp = NULL;
    char pid_str[MAX_LEN] = {0};
    int pid = -1;

    if ((fp = fopen(file_name, "rb")) != NULL)
    {
        if (fgets(pid_str, sizeof(pid_str), fp) != NULL && atoi(pid_str) > 0)
        {
            pid = atoi(pid_str);
        }
        fclose(fp);
    }

    if (pid > 0)
    {
        kill(pid, SIGUSR2);//Trigger release message
        sleep(1);
        unlink(file_name);
    }
    return;
}

static bool init_message_bus(void)
{
    char *pCfg = CCSP_MSG_BUS_CFG;
    if (!bus_handle)
    {
        int ret = CCSP_Message_Bus_Init("ccsp.gwprov", pCfg, &bus_handle, (CCSP_MESSAGE_BUS_MALLOC)Ansc_AllocateMemory_Callback, Ansc_FreeMemory_Callback);
        if (ret == -1)
        {
            GWPROV_PRINT("Failed to initialize message bus \n");
            bus_handle = NULL;
            return false;
        }
    }
    return true;
}

static int getIndex(char *lineOutput, char *parent)
{
    char *ptr = strstr(lineOutput, parent);
    int idx = 0;

    if (!ptr)
        return -1;

    ptr += strlen(parent);
    while (*ptr != '.')
    {
        idx = idx * 10 + (*ptr - '0');
        ptr++;
    }
    return idx;
}

static bool isParentMatch(char *object_name, char *parent)
{
    char *ptr = strstr(object_name, parent);
    if (!ptr || ptr[strlen(parent)] != '[')
        return false;
    return true;
}

static bool isAliasMatch(char *object_name, char *parent, char *alias)
{
    char param[1024];
    snprintf(param, sizeof(param), "%s[%s]", parent, alias);
    if (strstr(object_name, param) == NULL)
        return false;
    return true;
}
