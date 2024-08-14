/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2024 RDK Management
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
*/


/**************************************************************************/
/*      INCLUDES:                                                         */
/**************************************************************************/

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#if !defined(_PLATFORM_RASPBERRYPI_)
#include <sys/types.h>
#endif
#include <unistd.h>
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include <pthread.h>
#ifdef AUTOWAN_ENABLE
#include "autowan.h"
#include "gw_prov_sm.h"
#endif
#include <time.h>
#include "secure_wrapper.h"
#ifdef FEATURE_SUPPORT_RDKLOG
#include "rdk_debug.h"
#endif

#if defined (WIFI_MANAGE_SUPPORTED)
#include <ccsp_base_api.h>
#include "ccsp_memory.h"
#include "ccsp_psm_helper.h"
#endif /*WIFI_MANAGE_SUPPORTED*/

#include <telemetry_busmessage_sender.h>
#include "safec_lib_common.h"
#define DEBUG_INI_NAME  "/etc/debug.ini"

int gw_prov_sm_main(int argc, char *argv[]);

/**************************************************************************/
/*! \fn int main(int argc, char *argv)
 **************************************************************************
 *  \brief Init and run the Provisioning process
 *  \param[in] argc
 *  \param[in] argv
 *  \return Currently, never exits
 **************************************************************************/
int main(int argc, char *argv[])
{
    return gw_prov_sm_main(argc, argv);
}

