#  Copyright 2021 The casbin Authors. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

set(CASBIN_SOURCE_FILES
    abac_data.cpp
    enforcer.cpp
    enforcer_cached.cpp
    enforcer_synced.cpp
    internal_api.cpp
    logger.cpp
    management_api.cpp
    pch.cpp
    rbac_api.cpp
    rbac_api_with_domains.cpp
    config/config.cpp
    duktape/duktape.cpp
    effect/default_effector.cpp
    ip_parser/exception/parser_exception.cpp
    ip_parser/parser/allFF.cpp
    ip_parser/parser/CIDRMask.cpp
    ip_parser/parser/dtoi.cpp
    ip_parser/parser/equal.cpp
    ip_parser/parser/IP.cpp
    ip_parser/parser/IPNet.cpp
    ip_parser/parser/IPv4.cpp
    ip_parser/parser/parseCIDR.cpp
    ip_parser/parser/parseIP.cpp
    ip_parser/parser/parseIPv4.cpp
    ip_parser/parser/parseIPv6.cpp
    ip_parser/parser/Print.cpp
    ip_parser/parser/xtoi.cpp
    model/assertion.cpp
    model/function.cpp
    model/model.cpp
    model/scope_config.cpp
    persist/file_adapter/batch_file_adapter.cpp
    persist/file_adapter/file_adapter.cpp
    persist/file_adapter/filtered_file_adapter.cpp
    persist/adapter.cpp
    persist/default_watcher.cpp
    persist/default_watcher_ex.cpp
    rbac/default_role_manager.cpp
    util/array_equals.cpp
    util/array_remove_duplicates.cpp
    util/array_to_string.cpp
    util/built_in_functions.cpp
    util/ends_with.cpp
    util/escape_assertion.cpp
    util/find_all_occurences.cpp
    util/is_instance_of.cpp
    util/join.cpp
    util/join_slice.cpp
    util/remove_comments.cpp
    util/set_subtract.cpp
    util/split.cpp
    util/ticker.cpp
    util/trim.cpp
)

# Setting to C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)

add_library(casbin STATIC ${CASBIN_SOURCE_FILES})

target_precompile_headers(casbin PRIVATE pch.h)
target_include_directories(casbin PRIVATE ${CASBIN_SOURCE_DIR})

set_target_properties(casbin PROPERTIES 
    PREFIX ""
    VERSION ${CMAKE_PROJECT_VERSION}
)

if(WIN32 OR MSVC)
    set_target_properties(casbin PROPERTIES SUFFIX ".lib")
elseif(UNIX)
    set_target_properties(casbin PROPERTIES 
        SUFFIX ".a"
        POSITION_INDEPENDENT_CODE ON
    )
endif()
