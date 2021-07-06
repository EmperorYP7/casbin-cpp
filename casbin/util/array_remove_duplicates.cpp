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

#include "pch.h"

#ifndef ARRAY_REMOVE_DUPLICATES_CPP
#define ARRAY_REMOVE_DUPLICATES_CPP


#include <unordered_map>

#include "./util.h"

namespace casbin {

// ArrayRemoveDuplicates removes any duplicated elements in a std::string array.
void ArrayRemoveDuplicates(std::vector<std::string> &s) {
    CASBIN_VISUAL_PROFILE;
    std::unordered_map<std::string, bool> found;
    int j = 0;
    for (int i = 0 ; i < s.size() ; i++) {
        if (!found[s[i]]) {
            found[s[i]] = true;
            s[j] = s[i];
            j++;
        }
    }
    s = std::vector<std::string> (s.begin(), s.begin()+j);
}

} // namespace casbin

#endif // ARRAY_REMOVE_DUPLICATES_CPP
