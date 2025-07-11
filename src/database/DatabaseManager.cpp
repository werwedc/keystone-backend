#include "DatabaseManager.h"
#include <iostream>

DatabaseManager::DatabaseManager(std::string& connection_string) {
	m_connection_string = connection_string;
}

bool DatabaseManager::connect() {
	try { 
		m_connection = std::make_unique<pqxx::connection>(m_connection_string); 
		if (m_connection->is_open()) {
			std::cout << "Succesfully connected\n";
			return true;
		}
		else {
			std::cerr << "Connection object created but connection not opened\n";
			return false;
		}
	}
	catch (const std::exception& e) {
		std::cerr << "Database connection exception: " << e.what() << "\n";
		return false;
	}
}
