#include "pch.h"

#ifndef FILE_ADAPTER_CPP
#define FILE_ADAPTER_CPP


#include <fstream>

#include "./file_adapter.h"
#include "../../util/util.h"
#include "../../exception/io_exception.h"
#include "../../exception/unsupported_operation_exception.h"
#include "../../exception/casbin_adapter_exception.h"

namespace casbin {

// NewAdapter is the constructor for Adapter.
FileAdapter::FileAdapter(const std::string& file_path) {
    this->file_path = file_path;
    this->filtered = false;
}

// LoadPolicy loads all policy rules from the storage.
void FileAdapter::LoadPolicy(Model* model) {
    if (this->file_path == "")
        throw CasbinAdapterException("Invalid file path, file path cannot be empty");

    this->LoadPolicyFile(model, LoadPolicyLine);
}

// SavePolicy saves all policy rules to the storage.
void FileAdapter::SavePolicy(Model* model) {
    if (this->file_path == "") {
        throw CasbinAdapterException("Invalid file path, file path cannot be empty");
    }

    std::string tmp;

    for (std::unordered_map<std::string, std::shared_ptr<Assertion>>::iterator it = model->m["p"].assertion_map.begin() ; it != model->m["p"].assertion_map.begin() ; it++){
        for (int i = 0 ; i < it->second->policy.size() ; i++){
            tmp += it->first + ", ";
            tmp += ArrayToString(it->second->policy[i]);
            tmp += "\n";
        }
    }

    for (std::unordered_map <std::string, std::shared_ptr<Assertion>>::iterator it = model->m["g"].assertion_map.begin() ; it != model->m["g"].assertion_map.begin() ; it++){
        for (int i = 0 ; i < it->second->policy.size() ; i++){
            tmp += it->first + ", ";
            tmp += ArrayToString(it->second->policy[i]);
            tmp += "\n";
        }
    }

    return this->SavePolicyFile(std::string(RTrim(tmp, "\n")));
}

void FileAdapter::LoadPolicyFile(Model* model, void (*handler)(const std::string&, Model*)) {
    std::ifstream in_file;
    try {
        in_file.open(this->file_path);
    } catch (const std::ifstream::failure e) {
        throw IOException("Cannot open file.");
    }

    std::string line;
    while(getline(in_file, line, '\n')){
        line = Trim(line);
        handler(line, model);
    }

    in_file.close();
}

void FileAdapter::SavePolicyFile(std::string_view text) {
    std::ofstream out_file;
    out_file.open(this->file_path, std::ios::out);
    try {
        out_file.open(this->file_path, std::ios::out);
    } catch (const std::ifstream::failure e) {
        throw IOException("Cannot open file.");
    }

    out_file<<text;

    out_file.close();
}

// AddPolicy adds a policy rule to the storage.
void FileAdapter::AddPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) {
    throw UnsupportedOperationException("not implemented");
}

// RemovePolicy removes a policy rule from the storage.
void FileAdapter::RemovePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) {
    throw UnsupportedOperationException("not implemented");
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
void FileAdapter::RemoveFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values) {
    throw UnsupportedOperationException("not implemented");
}

// IsFiltered returns true if the loaded policy has been filtered.
bool FileAdapter::IsFiltered() {
    return this->filtered;
}

} // namespace casbin

#endif // FILE_ADAPTER_CPP
