#pragma once
#include <iostream>
#include <pqxx/pqxx>

class AccountManager {
public:
    AccountManager(pqxx::connection* db_connection);

    bool createAccount(const std::string& email, const std::string& password);
    bool deleteAccount(const std::string& email, const std::string& password);
    bool doesAccountExist(const std::string& email);
    bool isEmailValid(const std::string& email);
    bool isPasswordSecure(const std::string& password);
    bool sendVerificationEmail(const std::string& emai);
    bool sendPasswordResetEmail(const std::string& email, const std::string& password);
    bool changePass(const std::string& email, const std::string& new_password);
    std::string hash_password(const std::string& password);
    bool verifyAccount(const std::string& email);
    bool isVerified(const std::string& email);
    bool tryLogin(const std::string& email, const std::string& password);
private:
    pqxx::connection* m_db_connection;
};