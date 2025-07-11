#include "Server.h"
#include <iostream>

Server::Server() {

}

void Server::run() {
    Server::setupDatabase();
}

bool Server::setupDatabase() {
    DatabaseManager dbManager(database_conn_string);

    if (dbManager.connect()) {
        std::cout << "Succesfully connected to the database";
    }
    else {
        std::cerr << "Could not connect to the database. Exiting." << std::endl;
        return 1;
    }
}