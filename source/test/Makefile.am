##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

AM_CFLAGS =
AM_CXXFLAGS = -std=c++11

ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = gw_prov_gtest.bin

gw_prov_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest -I${top_srcdir}/gtest/include -I${top_srcdir}/source -I${top_srcdir}/source/include
gw_prov_gtest_bin_SOURCES = CcspGwProvAppTest.cpp ../gw_prov_sm_generic.c gtest_main.cpp
gw_prov_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -pthread

gw_prov_gtest_bin_LDADD = $(HOME)/usr/local/lib/libmock_safec_lib.la \
                          $(HOME)/usr/local/lib/libmock_file_io.la

# Adding Code Coverage Flags
AM_CFLAGS += -fprofile-arcs -ftest-coverage
AM_CXXFLAGS += -fprofile-arcs -ftest-coverage
gw_prov_gtest_bin_LDFLAGS += --coverage
