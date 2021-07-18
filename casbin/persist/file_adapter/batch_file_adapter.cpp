#include "pch.h"

#ifndef BATCH_FILE_ADAPTER_CPP
#define BATCH_FILE_ADAPTER_CPP


#include "./batch_file_adapter.h"
#include "../../exception/unsupported_operation_exception.h"

namespace casbin {

// NewAdapter is the constructor for Adapter.
BatchFileAdapter::BatchFileAdapter(const std::string& file_path): FileAdapter(file_path) {
}

void BatchFileAdapter::AddPolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules) {
    throw UnsupportedOperationException("not implemented hello");
}

void BatchFileAdapter::RemovePolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules) {
    throw UnsupportedOperationException("not implemented");
}

} // namespace casbin

#endif // BATCH_FILE_ADAPTER_CPP
