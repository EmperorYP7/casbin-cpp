/*
* Copyright 2020 The casbin Authors. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef CASBIN_CPP_PERSIST_DEFAULT_WATCHER_EX
#define CASBIN_CPP_PERSIST_DEFAULT_WATCHER_EX

#include "./watcher_ex.h"

namespace casbin {

class DefaultWatcherEx: public WatcherEx {
    public:

        void UpdateForAddPolicy(std::vector<std::string> params);

        void UpdateForRemovePolicy(std::vector<std::string> params);

        void UpdateForRemoveFilteredPolicy(int field_index, std::vector<std::string> field_values);

        void UpdateForSavePolicy(const std::shared_ptr<Model>& model);
};

};  // namespace casbin

#endif