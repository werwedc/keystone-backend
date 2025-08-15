#pragma once

#include "../crow/CrowApp.h"
#include "../database/DatabaseManager.h"
#include "client/AccountManager.h"
#include "applications/ApplicationsManager.h"
#include "licenses/LicenseManager.h"
#include "machines/MachinesManager.h"
#include "Config.h"

class Server {
public:
	Server(Config config);
	void run();
private:
    bool setupDatabase();
	void setupAccountManager();
	void setupApplicationsManager();
	void setupLicenseManager();
	void setupMachinesManager();
	void initializeLibSodium();
	void initializeRoutes();
	void runTests();
    std::unique_ptr<DatabaseManager> m_dbManager;
	std::unique_ptr<AccountManager> m_accountManager;
	std::unique_ptr<ApplicationsManager> m_applicationsManager;
	std::unique_ptr<LicenseManager> m_licenseManager;
	std::unique_ptr<MachinesManager> m_machinesManager;
	std::unique_ptr<CrowApp> m_crowApp;
	Config m_config;
};
