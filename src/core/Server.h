#pragma once
#include "../database/DatabaseManager.h"
#include "../client/AccountManager.h"
#include <iostream>

class Server {
public:
	Server();
	void run();
private:
	std::string database_conn_string{"dbname = keystone_db user = postgres password = werwedc hostaddr = 127.0.0.1 port = 5432"}; // Will be loaded from Config
    bool setupDatabase();
	void setupAccountManager();
	void initializeLibSodium();
	void runTests();
    std::unique_ptr<DatabaseManager> m_dbManager;
	std::unique_ptr<AccountManager> m_accountManager;
};
