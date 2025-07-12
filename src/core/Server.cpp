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
    runTests();
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
    pqxx::connection* db_connection_ptr = m_dbManager->getConnection();

    m_accountManager = std::make_unique<AccountManager>(*db_connection_ptr);
}

void Server::initializeLibSodium() {
    if (sodium_init() < 0) {
        std::cerr << "Error: Could not initialize libsodium!" << std::endl;
    }
    return;
}

void Server::runTests() {
    
}
