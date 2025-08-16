#include "AccountManager.h"
#include <vector>
#include <cctype>
#include <sodium.h>
#include <pqxx/pqxx>
#include <sstream>
#include <iomanip>
#include <iostream>

AccountManager::AccountManager(DatabaseManager& db_manager)
    : m_db_manager(db_manager)
{
}

/**
 * @brief Creates a new user account with a hashed password.
 * @details Hashes the provided password using Argon2ID and inserts a new record
 * into the `accounts` table with a default role of 'user'.
 * @param email The user's email address. Must be unique.
 * @param password The user's plain-text password.
 * @return True if the account was created successfully, false otherwise.
 */
bool AccountManager::createAccount(const std::string& email, const std::string& password)
{
    try {
        std::string password_hash = hash_password(password);

        auto conn = m_db_manager.getConnection();
        pqxx::work tx(*conn);
        std::string sql = "INSERT INTO accounts (email, password_hash, roles) "
            "VALUES ($1, $2, ARRAY['user']) RETURNING id;";

        pqxx::result result = tx.exec_params(sql, email, password_hash);
        tx.commit();

        if (!result.empty()) {
            int new_id = result[0][0].as<int>();
            std::cout << "Successfully created account with ID: " << new_id << std::endl;
            return true;
        }
        return false;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while creating account: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Deletes a user account from the database.
 * @param id The ID of the account to delete.
 * @return True if the deletion was successful, false otherwise.
 */
bool AccountManager::deleteAccount(int id)
{
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::work tx(*conn);
        std::string sql = "DELETE FROM accounts WHERE id = $1;";

        pqxx::result result = tx.exec_params(sql, id);
        tx.commit();
        return result.affected_rows() > 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while deleting account: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Checks if an account with the given email already exists.
 * @details Performs a case-insensitive search for the email address.
 * @param email The email address to check for.
 * @return True if an account with that email exists, false otherwise.
 */
bool AccountManager::doesAccountExist(const std::string& email)
{
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::read_transaction tx(*conn);
        std::string sql = "SELECT EXISTS(SELECT 1 FROM accounts WHERE LOWER(email) = LOWER($1));";
        pqxx::result result = tx.exec_params(sql, email);
        if (!result.empty()) {
            return result[0][0].as<bool>();
        }
        return false;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while checking if account exists: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Validates a password against a set of security rules.
 * @details Rules: minimum 8 characters, at least one uppercase letter, one lowercase letter,
 * one digit, and one special character.
 * @param password The password to validate.
 * @return True if the password meets all security requirements, false otherwise.
 */
bool AccountManager::isPasswordSecure(const std::string& password)
{
    if (password.length() < 8) return false;
    const std::string special_chars = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    if (password.find_first_of(special_chars) == std::string::npos) return false;
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    for (char ch : password) {
        if (isupper(ch)) hasUpper = true;
        if (std::islower(ch)) hasLower = true;
        if (isdigit(ch)) hasDigit = true;
    }
    if (!hasLower || !hasUpper || !hasDigit) return false;
    return true;
}

/**
 * @brief Changes the password for a given user.
 * @param id The ID of the user whose password is to be changed.
 * @param new_password The new plain-text password.
 * @return True if the password was changed successfully, false otherwise.
 */
bool AccountManager::changePass(int id, const std::string& new_password){
    try {
        std::string new_hash = hash_password(new_password);
        auto conn = m_db_manager.getConnection();
        pqxx::work tx(*conn);
        std::string sql = "UPDATE accounts SET password_hash = $1 WHERE id = $2;";
        pqxx::result result = tx.exec_params(sql, new_hash, id);
        tx.commit();
        return result.affected_rows() > 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while changing password: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Attempts to authenticate a user with an email and password.
 * @details This function is designed to be resistant to timing attacks. If a user does not exist,
 * it verifies the password attempt against a static fake hash to ensure the response time is
 * similar to that of a failed login for an existing user.
 * @param email The user's email address.
 * @param password_attempt The plain-text password to verify.
 * @return True if the credentials are valid, false otherwise.
 */
bool AccountManager::tryLogIn(const std::string& email, const std::string& password_attempt) {
    std::string stored_hash;
    std::string fake_hash = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$R+IM63_d5t41p1_a25DRRgn92XD3ZvoKx2fC2hddMAo";
    try {
        {
            auto conn = m_db_manager.getConnection();
            pqxx::read_transaction tx(*conn);
            std::string sql = "SELECT password_hash FROM accounts WHERE LOWER(email) = LOWER($1);";
            pqxx::result result = tx.exec_params(sql, email);

            if (!result.empty()) {
                stored_hash = result[0][0].as<std::string>();
            } else {
                stored_hash = fake_hash;
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error while checking credentials: " << e.what() << std::endl;
        return false;
    }
    if (crypto_pwhash_str_verify(
        stored_hash.c_str(),
        password_attempt.c_str(),
        password_attempt.length()
    ) != 0) {
        return false;
    }
    return true;
}

/**
 * @brief Retrieves account details for a given email address.
 * @param email The email address of the account to fetch.
 * @return An std::optional containing the AccountDetails struct if found, otherwise std::nullopt.
 */
std::optional<AccountDetails> AccountManager::getAccountDetails(const std::string& email)
{
    AccountDetails account_details{};
    try
    {
        auto conn = m_db_manager.getConnection();
        pqxx::read_transaction tx(*conn);
        std::string sql = "SELECT id, email, roles FROM accounts WHERE LOWER(email) = LOWER($1);";
        pqxx::result result = tx.exec_params(sql, email);

        if (!result.empty()) {
            account_details.id = result[0][0].as<int>();
            account_details.email = result[0][1].as<std::string>();
            account_details.roles = parsePgTextArray(result[0][2].as<std::string>());
            return account_details;
        }
        return std::nullopt;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while getting account details: " << e.what() << std::endl;
        return std::nullopt;
    }
}

/**
 * @brief Stores the SHA256 hash of a refresh token in the database for a specific user.
 * @param user_id The ID of the user to associate the token with.
 * @param refresh_token_hash The hashed refresh token.
 * @return True on successful update, false otherwise.
 */
bool AccountManager::storeRefreshTokenHash(int user_id, const std::string& refresh_token_hash)
{
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::work tx(*conn);
        std::string sql = "UPDATE accounts "
            "SET refresh_token_hash = $1 "
            "WHERE id = $2;";

        pqxx::result result = tx.exec_params(sql, refresh_token_hash, user_id);
        tx.commit();

        return result.affected_rows() > 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while storing refresh token hash: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Retrieves the stored refresh token hash for a user.
 * @param user_id The ID of the user whose token hash is to be fetched.
 * @return An std::optional containing the hash string if found, otherwise std::nullopt.
 */
std::optional<std::string> AccountManager::getRefreshTokenHash(int user_id)
{
    try
    {
        auto conn = m_db_manager.getConnection();
        pqxx::read_transaction tx(*conn);
        std::string sql = "SELECT refresh_token_hash FROM accounts WHERE id = $1;";
        pqxx::result result = tx.exec_params(sql, user_id);

        if (!result.empty()) {
            return result[0][0].as<std::string>();
        }
        return std::nullopt;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while getting refresh token hash: " << e.what() << std::endl;
        return std::nullopt;
    }
}

/**
 * @brief Deletes a user's refresh token hash from the database (e.g., during logout).
 * @param user_id The ID of the user whose token hash should be deleted.
 * @return True on successful update, false otherwise.
 */
bool AccountManager::deleteRefreshTokenHash(int user_id)
{
    try {
        auto conn = m_db_manager.getConnection();
        pqxx::work tx(*conn);
        std::string sql = "UPDATE accounts "
            "SET refresh_token_hash = NULL "
            "WHERE id = $1;";

        pqxx::result result = tx.exec_params(sql, user_id);
        tx.commit();

        return result.affected_rows() > 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error while deleting refresh token hash: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Hashes a string using SHA256. Used for refresh tokens.
 * @param token The plain-text token to hash.
 * @return A hex-encoded string representation of the SHA256 hash.
 */
std::string AccountManager::hash_token(const std::string& token)
{
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(
        hash,
        reinterpret_cast<const unsigned char*>(token.c_str()),
        token.length()
    );
    return bytes_to_hex(hash, sizeof(hash));
}

/**
 * @brief Hashes a password using libsodium's Argon2ID implementation.
 * @param password The plain-text password to hash.
 * @return A string containing the full password hash, including algorithm, salt, and parameters.
 */
std::string AccountManager::hash_password(const std::string& password)
{
    std::string hashed_password;
    hashed_password.resize(crypto_pwhash_STRBYTES);
    if (crypto_pwhash_str(
        &hashed_password[0],
        password.c_str(),
        password.length(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE
    ) != 0) {
        std::cerr << "Error: Out of memory or another error occurred during password hashing." << std::endl;
        return std::string();
    }
    hashed_password.resize(strlen(hashed_password.c_str()));
    return hashed_password;
}

/**
 * @brief Parses a PostgreSQL text array string into a vector of strings.
 * @warning This is a simple parser and may not handle all edge cases, such as
 * strings containing commas or quotes. Prefer using a more robust library or
 * `pqxx::field::to_array` if available and applicable.
 * @param pg_array_string The array as a string, e.g., `{"val1","val2"}`.
 * @return A vector of strings.
 */
std::vector<std::string> AccountManager::parsePgTextArray(const std::string& pg_array_string)
{
    std::vector<std::string> vec;
    vec.clear();

    bool is_writing = false;
    for (char c : pg_array_string) {
        std::string char_string{ c };
        if (c != '"' && c != '{' && c != '}' && c != ',') {
            if (is_writing) {
                vec.back().append(char_string);
            }
            else {
                is_writing = true;
                vec.push_back(char_string);
            }
        }
        else {
            is_writing = false;
        }
    }
    return vec;
}

/**
 * @brief Utility function to convert a byte array to a hex-encoded string.
 * @param bytes A pointer to the byte array.
 * @param len The length of the byte array.
 * @return A hex-encoded string.
 */
std::string AccountManager::bytes_to_hex(const unsigned char* bytes, size_t len)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return ss.str();
}
