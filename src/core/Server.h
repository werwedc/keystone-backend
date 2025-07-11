#pragma once
#include "../database/DatabaseManager.h"
#include <iostream>

class Server {
public:
	Server();
	void run();
private:
	std::string database_conn_string; // Will be loaded from Config
    bool setupDatabase();
    std::unique_ptr<DatabaseManager> m_dbManager;
};
