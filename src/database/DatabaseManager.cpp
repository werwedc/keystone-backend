#include "DatabaseManager.h"

DatabaseManager::DatabaseManager(std::string connection_string, size_t pool_size)
    : m_connection_string(std::move(connection_string)) {
    m_pool = std::make_unique<ConnectionPool>(pool_size, m_connection_string);
}

PooledConnection DatabaseManager::getConnection() {
    return m_pool->getConnection();
}