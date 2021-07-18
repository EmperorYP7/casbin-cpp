#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_BATCH_FILE_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_BATCH_FILE_ADAPTER

#include "./file_adapter.h"
#include "../batch_adapter.h"

namespace casbin {

class BatchFileAdapter: public BatchAdapter, public FileAdapter {
    public:

        // NewAdapter is the constructor for Adapter.
        BatchFileAdapter(const std::string& file_path);

        void AddPolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules);

        void RemovePolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules);
};

} // namespace casbin

#endif