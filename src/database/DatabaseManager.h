#pragma once
#include <pqxx/pqxx>
#include <iostream>

class DatabaseManager {
public:
	DatabaseManager(const std::string& connection_string);
	bool connect();
	pqxx::connection* getConnection();
private:
	std::string m_connection_string;
	std::unique_ptr<pqxx::connection> m_connection;
};