#include "core/Server.h"
#include "core/Config.h"

int main()
{
    auto configOpt = Config::load_from_env();
    if (!configOpt) {
        return 1;
    }

    Server server(std::move(*configOpt));
    server.run();
    
    return 0;
}