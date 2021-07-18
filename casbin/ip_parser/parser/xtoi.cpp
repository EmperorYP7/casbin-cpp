#include "pch.h"

#ifndef XTOI_CPP
#define XTOI_CPP


#include "./xtoi.h"

namespace casbin {

std::pair<int, int> xtoi(const std::string& s) {
    int n = 0;
    int i = 0;
    std::pair<int, int> p;
    for(const char character : s) {
        if('0' <= character && character <= '9') {
            n *= 16;
            n += static_cast<int>(character - '0');
        } else if('a' <= character && character <= 'f') {
            n *= 16;
            n += static_cast<int>(character - 'a') + 10;
        } else if('A' <= character && character <= 'F') {
            n *= 16;
            n += static_cast<int>(character - 'A') + 10;
        } else {
            break;
        }
        if(n >= big) {
            p.first = 0;
            p.second = i;
            return p;
        }
    }
    if(i == 0) {
        p.first = 0;
        p.second = i;
        return p;
    }
    p.first = n;
    p.second = i;
    return p;
}

} // namespace casbin

#endif // XTOI_CPP
