#include "Server.h"
#include <iostream>
#include "sodium.h"

Server::Server() {

}

void Server::run() {
    if (!setupDatabase()) {
        return;
    }
    setupAccountManager();
    setupApplicationsManager();
    setupLicenseManager();
    initializeLibSodium();
    runTests();
	initializeRoutes();
}

bool Server::setupDatabase() {
    m_dbManager = std::make_unique<DatabaseManager>(database_conn_string);

    if (m_dbManager->connect()) {
        std::cout << "Succesfully connected to the database\n";
    }
    else {
        std::cerr << "Could not connect to the database. Exiting." << std::endl;
        return false;
    }
    return true;
}

void Server::setupAccountManager() {
    m_accountManager = std::make_unique<AccountManager>(*m_dbManager);
}

void Server::setupApplicationsManager() {
    m_applicationsManager = std::make_unique<ApplicationsManager>(*m_accountManager, *m_dbManager);
}

void Server::setupLicenseManager() {
    m_licenseManager = std::make_unique<LicenseManager>(*m_applicationsManager, *m_dbManager);
}

void Server::initializeLibSodium() {
    if (sodium_init() < 0) {
        std::cerr << "Error: Could not initialize libsodium!" << std::endl;
    }
    return;
}

void Server::initializeRoutes() {
    m_crowApp = std::make_unique<CrowApp>(*m_accountManager, *m_applicationsManager, *m_licenseManager);
    m_crowApp->initializeRoutes();
	m_crowApp->run(8080);
}
void Server::runTests() {
    m_licenseManager->createLicense(2," ley", 1);
    m_licenseManager->addFlags(2, {"flag1", "flag2"});

}
