#pragma once
#include <pqxx/pqxx>
#include <iostream>

class DatabaseManager {
public:
	DatabaseManager(std::string& connection_string);
	bool connect();
private:
	std::string m_connection_string;
	std::unique_ptr<pqxx::connection> m_connection;
};