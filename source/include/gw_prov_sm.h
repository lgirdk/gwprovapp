#ifndef _GW_GWPROV_SM_H_
#define _GW_GWPROV_SM_H_
#ifdef AUTOWAN_ENABLE
#define DEBUG_INI_NAME  "/etc/debug.ini"
#define COMP_NAME "LOG.RDK.GWPROV"
#define LOG_INFO 4

#ifdef FEATURE_SUPPORT_RDKLOG
#define GWPROV_PRINT(fmt ...)    {\
                                     char _log_buff[1024]; \
                                     snprintf(_log_buff, sizeof(_log_buff), fmt);\
                                     RDK_LOG(LOG_INFO, COMP_NAME, "%s", _log_buff);\
                                 }
#else
#define GWPROV_PRINT printf
#endif
#endif
#endif
