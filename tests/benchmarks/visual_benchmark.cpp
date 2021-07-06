#include <casbin/casbin.h>
#include "casbin/pch.h"
#include "config_path.h"
#include <iostream>

static void BenchmarkRoleManagerMedium(int state) {
    CASBIN_VISUAL_PROFILE;
    casbin::Enforcer e(rbac_model_path);
    // Do not rebuild the role inheritance relations for every AddGroupingPolicy() call.
    e.EnableAutoBuildRoleLinks(false);
    std::vector<std::string> params(3);
    std::vector<std::string> g_params(2);

    // 100 roles, 10 resources.
    for (int i = 0; i < 100; ++i)
        params = {"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"}, e.AddPolicy(params);

    // 1000 users.
    for (int i = 0; i < 1000; ++i)
        g_params = {"user" + std::to_string(i), "group" + std::to_string(i / 10)}, e.AddGroupingPolicy(g_params);

    auto rm = e.GetRoleManager();

    for (int i = 0; i < state; ++i)
    {
        for (int j = 0; j < 100; ++j)
            rm->HasLink("user501", "group" + std::to_string(j));
     }
}

void RunBenchmarks() {
    CASBIN_VISUAL_PROFILE;
    BenchmarkRoleManagerMedium(5);
}

int main() {
    Instrumentor::Get().BeginSession("Main");
    RunBenchmarks();
    Instrumentor::Get().EndSession();
    std::cout << "Okay.";
    std::cin.get();
}