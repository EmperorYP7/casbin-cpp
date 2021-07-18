#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_FILE_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_FILE_ADAPTER

#include "../adapter.h"

namespace casbin {

// Adapter is the file adapter for Casbin.
// It can load policy from file or save policy to file.
class FileAdapter : virtual public Adapter {
    public:

        // NewAdapter is the constructor for Adapter.
        FileAdapter(const std::string& file_path);

        // LoadPolicy loads all policy rules from the storage.
        void LoadPolicy(Model* model);

        // SavePolicy saves all policy rules to the storage.
        void SavePolicy(Model* model);

        void LoadPolicyFile(Model* model, void (*handler)(const std::string&, Model*));

        void SavePolicyFile(const std::string& text);

        // AddPolicy adds a policy rule to the storage.
        void AddPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule);

        // RemovePolicy removes a policy rule from the storage.
        void RemovePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule);

        // RemoveFilteredPolicy removes policy rules that match the filter from the storage.
        void RemoveFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values);

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered();
};

};  // namespace casbin

#endif