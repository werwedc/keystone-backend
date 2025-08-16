#pragma once

#include "ConnectionPool.h"
#include <string>
#include <memory>

class DatabaseManager {
public:
    DatabaseManager(std::string connection_string, size_t pool_size = 10);
    
    PooledConnection getConnection();

private:
    std::string m_connection_string;
    std::unique_ptr<ConnectionPool> m_pool;
};