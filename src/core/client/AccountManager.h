#pragma once

#include <iostream>
#include <vector>
#include <cctype> 
#include <sodium.h>
#include <pqxx/pqxx>

struct AccountDetails {
    int id;
    std::string email;
    std::vector<std::string> roles;
};

class AccountManager {
public:
    AccountManager(pqxx::connection& db_connection);
    
    bool createAccount(const std::string& email, const std::string& password);
    bool deleteAccount(int user_id);
    bool doesAccountExist(const std::string& email);
    bool isPasswordSecure(const std::string& password);
    bool changePass(int user_id, const std::string& new_password);
    bool tryLogIn(const std::string& email, const std::string& password_attempt);
    // JWT 
    std::optional<AccountDetails> getAccountDetails(const std::string& email);
    bool storeRefreshTokenHash(int user_id, const std::string& refresh_token_hash);
    std::optional<std::string> getRefreshTokenHash(int user_id);
    bool deleteRefreshTokenHash(int user_id);
private:
    pqxx::connection& m_db_connection;
    std::string hash_password(const std::string& password);
    std::vector<std::string> parsePgTextArray(const std::string& pg_array_string);

};

