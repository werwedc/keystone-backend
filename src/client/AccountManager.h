#pragma once
#include <iostream>
#include <pqxx/pqxx>

class AccountManager {
public:
    AccountManager(pqxx::connection& db_connection);
    
    bool createAccount(const std::string& email, const std::string& password);
    bool deleteAccount(const std::string& email);
    bool doesAccountExist(const std::string& email);
    bool isPasswordSecure(const std::string& password);
    bool changePass(const std::string& email, const std::string& new_password);
    std::string hash_password(const std::string& password);
    bool tryLogIn(const std::string& email, const std::string& password_attempt);
private:
    pqxx::connection& m_db_connection;
};