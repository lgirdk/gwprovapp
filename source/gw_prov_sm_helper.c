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

#include <ccsp_alias_mgr.h>
#include <ccsp_alias_mgr_helper.h>
#include <syscfg/syscfg.h>

#include "gw_prov_sm_helper.h"

#include <cm_hal.h>

typedef struct _DmObject
{
    char Name[256];
    char Type[16];
    char Value[256];
    int  FailureCount;
    struct _DmObject *pNext;
} DmObject_t;

int cfgFileRouterMode = -1;

#define MAX_ARGS 20
#define MAX_LINE_SIZE 512
#define MAX_LEN 16
#define DHCPV4_PID_FILE "/var/run/eRT_ti_udhcpc.pid"
#define DHCPV6_PID_FILE "/var/run/erouter_dhcp6c.pid"

#define ALIAS_MANAGER_MAPPER_FILE "/usr/ccsp/custom_mapper.xml"

// globals for TLV202.43.12 processing
static DmObject_t *gpDmObjectHead = NULL;
static bool gbDmObjectParseCfgDone = false;
static int DmObjectSockFds[2];

static void Send_Release(char *file_name);

static int SaveRestartMask(unsigned long mask)
{
    unsigned long restart_mask = RESTART_NONE;
    char restart_module[32] = {0};
    char cmd[256];

    sysevent_get(sysevent_fd_gs, sysevent_token_gs, RESTART_MODULE, restart_module, sizeof(restart_module));
    if ( strlen(restart_module) > 0 )
    {
        restart_mask = strtoul(restart_module, NULL, 10);
    }
    restart_mask |= mask;
    snprintf(cmd, sizeof(cmd), "sysevent set %s %u", RESTART_MODULE, restart_mask);
    system(cmd);

    return 0;
}

int RestartServicesPerMask(void)
{
    unsigned long restart_mask = RESTART_NONE;
    char restart_module[32] = {0};
    char cmd[256];

    sysevent_get(sysevent_fd_gs, sysevent_token_gs, RESTART_MODULE, restart_module, sizeof(restart_module));
    if ( strlen(restart_module) > 0 )
    {
        restart_mask = strtoul(restart_module, NULL, 10);
    }
    if ( restart_mask != RESTART_NONE )
    {
        if ( restart_mask & RESTART_HOTSPOT )
        {
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "hotspot-restart", "", 0);
        }
        /* Note: Keep WIFI module as the last one */
        if ( restart_mask & RESTART_WIFI )
        {
            system("dmcli eRT setv Device.WiFi.Radio.1.X_CISCO_COM_ApplySetting bool true");
            system("dmcli eRT setv Device.WiFi.Radio.2.X_CISCO_COM_ApplySetting bool true");
        }
        snprintf(cmd, sizeof(cmd), "sysevent set %s %u", RESTART_MODULE, RESTART_NONE);
        system(cmd);
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
    return run_cmd_timeout(caller, cmd, retBuf, 200); // 10 second timeout (200 * 50ms)
}

void *GWP_start_hotspot_threadfunc(void *data)
{
    int timeout = 30;
    char erouter_ipv6[64];

    while(--timeout >= 0)
    {
        erouter_ipv6[0] = 0;
        sysevent_get(sysevent_fd_gs, sysevent_token_gs, "tr_erouter0_dhcpv6_client_v6addr", erouter_ipv6, sizeof(erouter_ipv6));
        if (erouter_ipv6[0] != 0)
        {
            fprintf(stderr,"=========eRouter IPv6 address got: %s=========\n", erouter_ipv6);
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "hotspot-restart", "", 0);
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
        system("sysevent set reboot-triggered 1");
        GWP_UpdateERouterMode();
        sleep(5);
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

/**************************************************************************/
/*! \fn bool GW_CheckForErrorStr(FILE *pFile, char *errorStr);
 **************************************************************************
 *  \brief Check for specified error in a result file
 *  \param[in] pFile - File to read result data from
 *  \param[in] errorStr - Error string to look for
 *  \return true - errorStr was found, false - errorStr was not found
 **************************************************************************/
static bool GW_CheckForErrorStr(FILE *pFile, char *errorStr)
{
    char buf[256];

    while (fgets(buf, sizeof(buf), pFile) != NULL)
    {
        if (strstr(buf, errorStr) != NULL)
        {
            // error found
            return true;
        }
    }
    return false;
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
static bool GW_SetParam(const char *pName, const char *pType, const char *pValue)
{
    char cmd[1024];
    bool success = false;
    FILE *result = NULL;

    if (pName == NULL || pType == NULL || pValue == NULL)
    {
        return false;
    }

    /* Skip WiFi Apply TLV */
    if ( strstr(pName, DEVICE_WIFI) != NULL && strstr(pName, DEVICE_WIFI_APPLY) != NULL )
    {
        return true;
    }

    /* Call dmcli to apply the parameter. This really needs to be reworked to use d-bus
       transactions directly. That is something for future enhancement. */
    snprintf(cmd, sizeof(cmd), "dmcli eRT setvalues '%s' %s '%s'", pName, pType, pValue);

    /* Retry on "Can't find dest component" error to workaround startup timing sensitivity */
    result = popen(cmd, "r");
    if (result)
    {
        success = !GW_CheckForErrorStr(result, "Can't find destination component");
        pclose(result);
    }
    /* keep a flag if we ever set a WiFi param so we can apply settings later */
    if (success)
    {
        unsigned long restart_mask = RESTART_NONE;
        if ( strncmp(pName, DEVICE_HOTSPOT, sizeof(DEVICE_HOTSPOT)-1) == 0 )
        {
             restart_mask |= RESTART_HOTSPOT;
             restart_mask |= RESTART_WIFI;
        }
        if ( strncmp(pName, DEVICE_WIFI, sizeof(DEVICE_WIFI)-1) == 0 )
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
/*! \fn bool GW_DmObjectListIsEmpty(void);
 **************************************************************************
 *  \brief Determines if DataModel list is empty
 *  \return bool - true if the list is empty
 **************************************************************************/
static bool GW_DmObjectListIsEmpty(void)
{
    return (gpDmObjectHead == NULL);
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

    while (pCurr != NULL)
    {
        /* GW_SetParam() only returns failure if the parameter could not be found... it can still fail
           for invalid value, etc., but in those cases we don't want to retry because there is no point */
        success = GW_SetParam(pCurr->Name, GW_MapTr69TypeToDmcliType(pCurr->Type), pCurr->Value);
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
/**************************************************************************/
/*! \fn bool is_customer_data_model()
 **************************************************************************
 *  \brief Check whether customer data-model is in place
 *  \return true if the customer data-model is enabled
 **************************************************************************/
static bool is_customer_data_model (void)
{
    char sysbuf[8];

    syscfg_get (NULL, "custom_data_model_enabled", sysbuf, sizeof(sysbuf));

    if (strcmp (sysbuf, "1") == 0)
    {
        return true;
    }

    return false;
}

/**************************************************************************/
/*! \fn bool GW_DmObjectThread(void *pParam);
 **************************************************************************
 *  \brief Worker thread to process VendorSpecific Sub TLVs (TLV202.43.x)
 *  \param[in] pParam - unused
 *  \return void * - unused
 **************************************************************************/
static void *GW_DmObjectThread(void *pParam)
{
    char cmd[1024];
    char *cmd_output = NULL;
    int ret = -1, i;
    long inst = -1;
    char *parent, *alias, *p, *parameterName;
    ANSC_HANDLE aliasMgr = NULL;         // AliasManager handle for DataModel names' aliasing
    char *internalName;

    /* copy to local buffer so we can manipulate it */
    char tlvData[GW_SUBTLV_VENDOR_SPECIFIC_DATAMODEL_OBJECT_MAX_LEN + 1];

    if (is_customer_data_model())
    {
        aliasMgr = CcspAliasMgrInitialize();

        if (!CcspAliasMgrLoadMappingFile(aliasMgr, ALIAS_MANAGER_MAPPER_FILE))
        {
            printf("gw-prov-app: Failed to load alias mapping file %s\n", ALIAS_MANAGER_MAPPER_FILE);
            CcspAliasMgrFree(aliasMgr);
            aliasMgr = NULL;
        }
        else
        {
            printf("gw-prov-app: customer data-model %s successfully loaded\n", ALIAS_MANAGER_MAPPER_FILE);
        }
    }

    sleep(180); // It takes around 3 minutes for ccsp components to come online from this point
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
        if (!GW_DmObjectListIsEmpty())
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

                if (aliasMgr != NULL)
                {
                    internalName = CcspAliasMgrGetFirstInternalName(aliasMgr, dmObject.Name);

                    if (internalName)
                    {
                        printf("gw-prov-app: replacing TLV202.43.12 parameter %s with internal name %s\n", dmObject.Name, internalName);
                        strncpy(dmObject.Name, internalName, sizeof(dmObject.Name) - 1);
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

                if(strstr(dmObject.Name,"["))
                {
                    int flag = 0;
                    parent = strtok(dmObject.Name, "[");
                    alias = strtok(NULL, "]");
                    parameterName = strtok(NULL,"].");

                    snprintf(cmd, sizeof(cmd), "dmcli eRT getnames %s",parent);
                    ret = run_cmd(__func__,cmd, &cmd_output);
                    if(cmd_output != NULL)
                    {
                        inst = find_instance(cmd_output, parent);
                        free(cmd_output);
                    }
                    for(i=1;i<=inst;i++)
                    {
                        snprintf(cmd, sizeof(cmd), "dmcli eRT getvalues %s%d.Alias",parent,i);
                        ret = run_cmd(__func__,cmd, &cmd_output);

                        if(cmd_output != NULL)
                        {
                            if(check_alias(cmd_output, alias))
                            {
                                free(cmd_output);
                                flag = 1;
                                snprintf(cmd, sizeof(cmd) - 1, "%s%d.%s", parent, i, parameterName);
                                strncpy(dmObject.Name, cmd, sizeof(dmObject.Name)-1);
                                break;
                            }
                            free(cmd_output);
                        }
                    }

                    if(!flag)
                    {
                        snprintf(cmd, sizeof(cmd), "dmcli eRT addtable %s ", parent);
                        ret = run_cmd(__func__,cmd, &cmd_output);
                        if(cmd_output != NULL)
                        {
                            inst = find_instance(cmd_output, parent);
                            free(cmd_output);
                            snprintf(cmd, sizeof(cmd), "%s%d.Alias", parent, inst);
                            if(!GW_SetParam(cmd,"string", alias))
                            {
                                DmObject_t AliasObject;
                                strncpy(AliasObject.Name, cmd, sizeof(AliasObject.Name)-1);
                                strncpy(AliasObject.Type, "string", sizeof(AliasObject.Type)-1);
                                strncpy(AliasObject.Value, alias, sizeof(AliasObject.Value)-1);
                                GW_DmObjectListAdd(&AliasObject);
                            }
                            snprintf(cmd, sizeof(cmd), "%s%d.%s", parent, inst, parameterName);
                            strncpy(dmObject.Name, cmd, sizeof(dmObject.Name)-1);
                        }
                    }
                }
                /* GW_SetParam() only returns failure if the parameter could not be found... it can still fail
                   for invalid value, etc., but in those cases we don't want to retry because there is no point */
                if (!GW_SetParam(dmObject.Name, pTypeDmcli, dmObject.Value))
                {
                    dmObject.FailureCount++;
                    GW_DmObjectListAdd(&dmObject);
                }
            }
        }

        /* if there was no new TLV to process, try to handle our queued list */
        else if (!GW_DmObjectListIsEmpty())
        {
            GW_DmObjectListApply();
        }

        /* if config processing is done, AND our queued list is empty, AND we set some WiFi thing,
           then go ahead and apply those WiFi setting (yet another WiFi restart, yeehaw) */
        if (gbDmObjectParseCfgDone && GW_DmObjectListIsEmpty())
        {
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "cfgfile_status", "End", 0);
            sysevent_set(sysevent_fd_gs, sysevent_token_gs, "cfgfile_apply", "", 0);
            gbDmObjectParseCfgDone = false;
        }
    }

    if (aliasMgr)
    {
        CcspAliasMgrFree(aliasMgr);
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

