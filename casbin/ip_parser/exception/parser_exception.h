#ifndef IP_PARSER_EXCEPTIONS_PARSE_EXCEPTION
#define IP_PARSER_EXCEPTIONS_PARSE_EXCEPTION

#include <string>

namespace casbin {

class ParserException {
    std::string error_message;
    public:
        ParserException(const std::string& error_message);
};

} // namespace casbin

#endif