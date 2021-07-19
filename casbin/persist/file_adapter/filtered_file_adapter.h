#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_FILTERED_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_FILTERED_ADAPTER

#include "file_adapter.h"
#include "../filtered_adapter.h"

namespace casbin {

class FilteredFileAdapter : public FileAdapter, public FilteredAdapter {
    private:

        static bool filterLine(const std::string& line, Filter* filter);

        static bool filterWords(std::vector<std::string>& line, std::vector<std::string>& filter);

        void loadFilteredPolicyFile(Model* model, Filter* filter, void (*handler)(const std::string&, Model*));

    public:

        // NewFilteredAdapter is the constructor for FilteredAdapter.
        FilteredFileAdapter(const std::string& file_path);

        // LoadPolicy loads all policy rules from the storage.
        void LoadPolicy(Model* model);

        // LoadFilteredPolicy loads only policy rules that match the filter.
        void LoadFilteredPolicy(Model* model, Filter* filter);

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered();

        // SavePolicy saves all policy rules to the storage.
        void SavePolicy(Model* model);
};

};  // namespace casbin

#endif