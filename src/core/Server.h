#pragma once
#include "../database/DatabaseManager.h"
#include "client/AccountManager.h"
#include "applications/ApplicationsManager.h"
#include "../crow/CrowApp.h"
#include <iostream>

#include "licenses/LicenseManager.h"

class Server {
public:
	Server();
	void run();
private:
	std::string database_conn_string{"dbname = keystone_db user = postgres password = werwedc hostaddr = 127.0.0.1 port = 5432"}; // Will be loaded from Config
    bool setupDatabase();
	void setupAccountManager();
	void setupApplicationsManager();
	void setupLicenseManager();
	void initializeLibSodium();
	void initializeRoutes();
	void runTests();
    std::unique_ptr<DatabaseManager> m_dbManager;
	std::unique_ptr<AccountManager> m_accountManager;
	std::unique_ptr<ApplicationsManager> m_applicationsManager;
	std::unique_ptr<LicenseManager> m_licenseManager;
	std::unique_ptr<CrowApp> m_crowApp;
};
