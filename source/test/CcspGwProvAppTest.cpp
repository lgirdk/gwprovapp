/*
* If not stated otherwise in this file or this component's LICENSE
* file the following copyright and licenses apply:
*
* Copyright 2015 RDK Management
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

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <experimental/filesystem>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_file_io.h>
#include <cstring>
#include <cerrno>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_file_io.h>
#include <mocks/mock_ethsw_hal.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_securewrapper.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_telemetry.h>

SafecLibMock *g_safecLibMock = NULL;
FileIOMock *g_fileIOMock = NULL;
EthSwHalMock *g_ethSwHALMock = NULL;
SyscfgMock *g_syscfgMock = NULL;
SecureWrapperMock *g_securewrapperMock = NULL;
SyseventMock *g_syseventMock = NULL;
telemetryMock *g_telemetryMock = NULL;


using namespace std;
using std::experimental::filesystem::exists;
using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::HasSubstr;
using ::testing::SetArgPointee;
using ::testing::DoAll;

extern "C" {
#include "gw_prov_sm.h"
#include "autowan.h"
typedef enum {
    EROUTER_MODE_INTERNAL,
    EROUTER_MODE,
    IPV4STATUS,
    IPV6STATUS,
    SYSTEM_RESTART,
    BRING_LAN,
    PNM_STATUS,
    PING_STATUS,
    CONN_STATUS,
    SNMP_SUBAGENT_STATUS,
    PRIMARY_LAN_13NET,
    LAN_STATUS,
    BRIDGE_STATUS,
    DHCPV6_CLIENT_V6ADDR,
    WAN_STATUS,
    IPV6_PREFIX,
    NTP_TIME_SYNC,
    FIREWALL_RESTART,
    WEBUI_FLAG_RESET,
    GWP_THREAD_ERROR
} eGwpThreadType;
typedef enum
{
    DOCESAFE_ENABLE_DISABLE_extIf,
    DOCESAFE_ENABLE_IPv4_extIf,
    DOCESAFE_ENABLE_IPv6_extIf,
    DOCESAFE_ENABLE_IPv4_IPv6_extIf,

    DOCESAFE_ENABLE_NUM_ENABLE_TYPES_extIf
} DOCSIS_Esafe_Db_extIf_e;
#define ER_NETDEVNAME "erouter0"
#define BRMODE_ROUTER 0
#define BRMODE_PRIMARY_BRIDGE   3
#define BRMODE_GLOBAL_BRIDGE 2
void GWP_Util_get_shell_output( char *cmd, char *out, int len );
void getMultiCastGroupAddress(unsigned char *inetAddr, unsigned char *inetMcgrpAddr);
pid_t findProcessId(char *processName);
eGwpThreadType Get_GwpThreadType(char *name);
int GWPEthWan_SysCfgGetInt(const char *name);
int IsEthWanEnabled(void);
int GWPETHWAN_SysCfgSetInt(const char *name, int int_value);
void validate_mode(int *bridge_mode);
int getSyseventBridgeMode(int erouterMode, int bridgeMode);
void GWPEthWan_EnterBridgeMode(void);
void GWPEthWan_EnterRouterMode(void);
void UpdateActiveDeviceMode();
void GWPEthWan_ProcessUtopiaRestart(void);
int GWP_SysCfgGetInt(const char *name);
void check_lan_wan_ready();
void LAN_start();
}

extern void GWP_Util_get_shell_output(char *cmd, char *out, int len);

class GwProvFixture : public ::testing::Test {
protected:
    void SetUp() override {
        g_safecLibMock = new SafecLibMock();
        g_fileIOMock = new FileIOMock();
        g_ethSwHALMock = new EthSwHalMock();
        g_syscfgMock = new SyscfgMock();
        g_securewrapperMock = new SecureWrapperMock();
        g_syseventMock = new SyseventMock();
        g_telemetryMock = new telemetryMock();
    }

    void TearDown() override {
        delete g_safecLibMock;
        delete g_fileIOMock;
        delete g_ethSwHALMock;
        delete g_syscfgMock;
        delete g_securewrapperMock;
        delete g_syseventMock;
        delete g_telemetryMock;

        g_safecLibMock = nullptr;
        g_fileIOMock = nullptr;
        g_ethSwHALMock = nullptr;
        g_syscfgMock = nullptr;
        g_securewrapperMock = nullptr;
        g_syseventMock = nullptr;
        g_telemetryMock = nullptr;

    }
};

TEST_F(GwProvFixture, ValidAddresses)
{
    unsigned char inetAddr[16];
    unsigned char inetMcgrpAddr[16];
    memset(inetAddr, 0, sizeof(inetAddr));
    memset(inetMcgrpAddr, 0, sizeof(inetMcgrpAddr));
    inetAddr[13] = 0x12;
    inetAddr[14] = 0x34;
    inetAddr[15] = 0x56;

    const unsigned char expectedMcgrpAddr[16] = {
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0xff, 0x00, 0x12, 0x34, 0x56
    };

    getMultiCastGroupAddress(inetAddr, inetMcgrpAddr);

    for (int i = 0; i < 16; i++) {
        EXPECT_EQ(inetMcgrpAddr[i], expectedMcgrpAddr[i]);
    }
}

TEST_F(GwProvFixture, TestSuccess)
{
    const char* command = "Hello";
    char output[32] = {0};
    FILE* mockFile = (FILE*)0x1234;
    char mockBuf[] = "Hello";

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(command), StrEq("r")))
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
         .Times(1)
        .WillOnce(DoAll(testing::SetArrayArgument<0>(mockBuf, mockBuf + sizeof(mockBuf) - 1), Return(mockBuf)));

    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, StrEq(mockBuf), _))
        .WillOnce(DoAll(testing::SetArrayArgument<0>(mockBuf, mockBuf + sizeof(mockBuf) - 1), Return(0)));

    GWP_Util_get_shell_output(const_cast<char*>(command), output, 32);

    EXPECT_STREQ(output, "Hello");
}

TEST_F(GwProvFixture, TestSuccess1)
{
    char processName[] = "Hello";
    char request[256], response[256];
    FILE* mockFile = (FILE*)0x1234;
    char mockBuf[] = "Hello";
    char mockPID[] = "123";

    {
    testing::InSequence s;
    EXPECT_CALL(*g_fileIOMock, popen(StrEq("ps  | grep Hello"), StrEq("r")))
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
         .Times(1)
        .WillOnce(DoAll(testing::SetArrayArgument<0>(mockBuf, mockBuf + sizeof(mockBuf) - 1), Return(mockBuf)));

    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq("pidof Hello"), StrEq("r")))
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(StrEq(mockBuf), _, _))
         .Times(1)
        .WillOnce(DoAll(testing::SetArrayArgument<0>(mockPID, mockPID + sizeof(mockPID) - 1), Return(mockPID)));
 
    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .WillOnce(Return(0));
    }

    EXPECT_EQ(findProcessId(processName), 123);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_erouterModeInternal)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = EROUTER_MODE_INTERNAL;
    const char *mockBuf = "erouterModeInternal";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_erouterMode)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = EROUTER_MODE;
    const char *mockBuf = "erouter_mode";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_ipv4Status)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = IPV4STATUS;
    const char *mockBuf = "ipv4-status";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_ipv6Status)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = IPV6STATUS;
    const char *mockBuf = "ipv6-status";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_systemRestart)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = SYSTEM_RESTART;
    const char *mockBuf = "system-restart";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_bringLan)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = BRING_LAN;
    const char *mockBuf = "bring-lan";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_pnmStatus)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = PNM_STATUS;
    const char *mockBuf = "pnm-status";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_pingStatus)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = PING_STATUS;
    const char *mockBuf = "ping-status";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_connStatus)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = CONN_STATUS;
    const char *mockBuf = "conn-status";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_snmpSubagentStatus)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = SNMP_SUBAGENT_STATUS;
    const char *mockBuf = "snmp_subagent-status";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("snmp_subagent-status"),
                                               strlen("snmp_subagent-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_primaryLan13Net)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = PRIMARY_LAN_13NET;
    const char *mockBuf = "primary_lan_l3net";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("snmp_subagent-status"),
                                               strlen("snmp_subagent-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("primary_lan_l3net"),
                                               strlen("primary_lan_l3net"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_lanStatus)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = LAN_STATUS;
    const char *mockBuf = "lan-status";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1); 
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("snmp_subagent-status"),
                                               strlen("snmp_subagent-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("primary_lan_l3net"),
                                               strlen("primary_lan_l3net"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("lan-status"),
                                               strlen("lan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_bridgeStatus)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = BRIDGE_STATUS;
    const char *mockBuf = "bridge-status";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("snmp_subagent-status"),
                                               strlen("snmp_subagent-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("primary_lan_l3net"),
                                               strlen("primary_lan_l3net"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("lan-status"),
                                               strlen("lan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bridge-status"),
                                               strlen("bridge-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_dhcpv6ClientV6Addr) 
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = DHCPV6_CLIENT_V6ADDR;
    const char *mockBuf = "tr_erouter0_dhcpv6_client_v6addr";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("snmp_subagent-status"),
                                               strlen("snmp_subagent-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("primary_lan_l3net"),
                                               strlen("primary_lan_l3net"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("lan-status"),
                                               strlen("lan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bridge-status"),
                                               strlen("bridge-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("tr_erouter0_dhcpv6_client_v6addr"),
                                               strlen("tr_erouter0_dhcpv6_client_v6addr"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_wanStatus)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = WAN_STATUS;
    const char *mockBuf = "wan-status";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("snmp_subagent-status"),
                                               strlen("snmp_subagent-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("primary_lan_l3net"),
                                               strlen("primary_lan_l3net"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("lan-status"),
                                               strlen("lan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bridge-status"),
                                               strlen("bridge-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("tr_erouter0_dhcpv6_client_v6addr"),
                                               strlen("tr_erouter0_dhcpv6_client_v6addr"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("wan-status"),
                                               strlen("wan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_ipv6Prefix)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = IPV6_PREFIX;
    const char *mockBuf = "ipv6_prefix";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("snmp_subagent-status"),
                                               strlen("snmp_subagent-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("primary_lan_l3net"),
                                               strlen("primary_lan_l3net"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("lan-status"),
                                               strlen("lan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bridge-status"),
                                               strlen("bridge-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("tr_erouter0_dhcpv6_client_v6addr"),
                                               strlen("tr_erouter0_dhcpv6_client_v6addr"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("wan-status"),
                                               strlen("wan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6_prefix"),
                                               strlen("ipv6_prefix"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_ntpTimeSync)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = NTP_TIME_SYNC;
    const char *mockBuf = "ntp_time_sync";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("snmp_subagent-status"),
                                               strlen("snmp_subagent-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("primary_lan_l3net"),
                                               strlen("primary_lan_l3net"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("lan-status"),
                                               strlen("lan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bridge-status"),
                                               strlen("bridge-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("tr_erouter0_dhcpv6_client_v6addr"),
                                               strlen("tr_erouter0_dhcpv6_client_v6addr"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("wan-status"),
                                               strlen("wan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6_prefix"),
                                               strlen("ipv6_prefix"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ntp_time_sync"),
                                               strlen("ntp_time_sync"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_firewallRestart)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = FIREWALL_RESTART;
    const char *mockBuf = "firewall-restart";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("snmp_subagent-status"),
                                               strlen("snmp_subagent-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("primary_lan_l3net"),
                                               strlen("primary_lan_l3net"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("lan-status"),
                                               strlen("lan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bridge-status"),
                                               strlen("bridge-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("tr_erouter0_dhcpv6_client_v6addr"),
                                               strlen("tr_erouter0_dhcpv6_client_v6addr"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("wan-status"),
                                               strlen("wan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6_prefix"),
                                               strlen("ipv6_prefix"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ntp_time_sync"),
                                               strlen("ntp_time_sync"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("firewall-restart"),
                                               strlen("firewall-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGetGwpThreadType_webuiFlagReset)
{
    eGwpThreadType ret = GWP_THREAD_ERROR;
    eGwpThreadType expected = WEBUI_FLAG_RESET;
    const char *mockBuf = "webuiStartedFlagReset";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouterModeInternal"),
                                               strlen("erouterModeInternal"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("erouter_mode"),
                                               strlen("erouter_mode"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv4-status"),
                                               strlen("ipv4-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6-status"),
                                               strlen("ipv6-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("system-restart"),
                                               strlen("system-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bring-lan"),
                                               strlen("bring-lan"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("pnm-status"),
                                               strlen("pnm-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ping-status"),
                                               strlen("ping-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("conn-status"),
                                               strlen("conn-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("snmp_subagent-status"),
                                               strlen("snmp_subagent-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("primary_lan_l3net"),
                                               strlen("primary_lan_l3net"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("lan-status"),
                                               strlen("lan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("bridge-status"),
                                               strlen("bridge-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("tr_erouter0_dhcpv6_client_v6addr"),
                                               strlen("tr_erouter0_dhcpv6_client_v6addr"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("wan-status"),
                                               strlen("wan-status"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ipv6_prefix"),
                                               strlen("ipv6_prefix"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ntp_time_sync"),
                                               strlen("ntp_time_sync"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("firewall-restart"),
                                               strlen("firewall-restart"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("webuiStartedFlagReset"),
                                               strlen("webuiStartedFlagReset"),
                                               StrEq(mockBuf), _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));

    ret = Get_GwpThreadType((char *)mockBuf);
    EXPECT_EQ(ret, expected);
}

TEST_F(GwProvFixture, TestGWPEthWan_SysCfgGetInt)
{
    int ret = -1;
    const char *name = "bridge_mode";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(1);

    ret = GWPEthWan_SysCfgGetInt(name);
    EXPECT_EQ(ret, 0);
}

TEST_F(GwProvFixture, TestIsEthWanEnabled)
{
    int ret = -1;
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(1);

    ret = IsEthWanEnabled();
    EXPECT_EQ(ret, 0);
}


TEST_F(GwProvFixture, TestGWPETHWAN_SysCfgSetInt)
{
    int ret = -1;
    const char *name = "bridge_mode";
    int int_value = 1;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u(_, _))
        .Times(1);

    ret = GWPETHWAN_SysCfgSetInt(name, int_value);
    EXPECT_EQ(ret, 0);
}

TEST_F(GwProvFixture, Testvalidate_mode)
{
    int bridge_mode = 1;
    EXPECT_CALL(*g_syscfgMock, syscfg_commit())
        .Times(1);

    validate_mode(&bridge_mode);
}

TEST_F(GwProvFixture, getSyseventBridgeMode_erouterMode1_bridgeMode2)
{
    int ret = -1;
    int bridgemode = 2;
    int eroutermode = 1;

    ret = getSyseventBridgeMode(eroutermode, bridgemode);
    EXPECT_EQ(ret, BRMODE_GLOBAL_BRIDGE);
}

TEST_F(GwProvFixture, getSyseventBridgeMode_erouterMode1_bridgeMode3)
{
    int ret = -1;
    int bridge_mode = 3;
    int erouter_mode = 1;

    ret = getSyseventBridgeMode(erouter_mode, bridge_mode);
    EXPECT_EQ(ret, BRMODE_PRIMARY_BRIDGE);
}

TEST_F(GwProvFixture, getSyseventBridgeMode_erouterMode1_bridgeMode0)
{
    int ret = 0;
    int bridge_mode = 10;
    int erouter_mode = 1;

    ret = getSyseventBridgeMode(erouter_mode, bridge_mode );
    EXPECT_EQ(ret, BRMODE_ROUTER);
}

TEST_F(GwProvFixture, getSyseventBridgeMode_erouterMode0_bridgeMode0)
{
    int ret = 2;
    int bridge_mode = 0;
    int erouter_mode = 0;

    ret = getSyseventBridgeMode(erouter_mode, bridge_mode );
    EXPECT_EQ(ret, BRMODE_GLOBAL_BRIDGE);
}

TEST_F(GwProvFixture, TestGWPEthWan_EnterBridgeMode)
{
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(1);
 
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_, _))
        .Times(1);

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_, _))
        .Times(2);

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(2);

    GWPEthWan_EnterBridgeMode();
    EXPECT_EQ(0, 0);
}

TEST_F(GwProvFixture, TestGWPEthWan_EnterRouterMode)
{
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(1);

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_, _))
        .Times(2);

    GWPEthWan_EnterRouterMode();
    EXPECT_EQ(0, 0);
}

TEST_F(GwProvFixture, TestUpdateActiveDeviceMode)
{
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(1);

    UpdateActiveDeviceMode();
 }

TEST_F(GwProvFixture, TestGWPEthWan_ProcessUtopiaRestart)
{
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(1);

    GWPEthWan_ProcessUtopiaRestart();
}

TEST_F(GwProvFixture, ProcessUtopiaRestart_BRMODE_ROUTER)
{
     int active_mode = BRMODE_ROUTER;

     GWPEthWan_EnterRouterMode();

     GWPEthWan_ProcessUtopiaRestart();
}

TEST_F(GwProvFixture, ProcessUtopiaRestart_BRMODE_PRIMARY_BRIDGE)
{
     int active_mode = BRMODE_PRIMARY_BRIDGE;

     GWPEthWan_EnterRouterMode();

     GWPEthWan_ProcessUtopiaRestart();
}

TEST_F(GwProvFixture, ProcessUtopiaRestart_BRMODE_GLOBAL_BRIDGE)
{
     int active_mode = BRMODE_GLOBAL_BRIDGE;

     GWPEthWan_EnterRouterMode();

     GWPEthWan_ProcessUtopiaRestart();
}

TEST_F(GwProvFixture, TestGWP_SysCfgGetInt)
{
    int ret = -1;
    const char *name = "bridge_mode";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(1);

    ret = GWP_SysCfgGetInt(name);
    EXPECT_EQ(ret, 0);
}

TEST_F(GwProvFixture, Testcheck_lan_wan_ready_1)
{
    int bridge_mode = 0;
    int eRouterMode = 0;
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(4);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(1);
    check_lan_wan_ready();
}

TEST_F(GwProvFixture, Testcheck_lan_wan_ready_2)
{
    int bridge_mode = 1;
    int eRouterMode = 0;
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(4);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(1);
    check_lan_wan_ready();
}

TEST_F(GwProvFixture, Testcheck_lan_wan_ready_3)
{
    int bridge_mode = 0;
    int eRouterMode = 1;
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(EOK)));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, _, _, _))
        .Times(4);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(1);
    check_lan_wan_ready();
}

TEST_F(GwProvFixture, TestLAN_start)
{
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _))
        .Times(2);
    LAN_start();
}