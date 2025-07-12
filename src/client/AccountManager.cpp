#include "AccountManager.h"
#include <vector>
#include <string>
#include <sodium.h>

AccountManager::AccountManager(pqxx::connection* db_connection) {
	m_db_connection = db_connection;
}

//Assumes email valid, account not exist, password secure
bool AccountManager::createAccount(const std::string& email, const std::string& password)
{
	std::string password_hash = hash_password(password);

	pqxx::work tx(*m_db_connection);
	std::string sql = "INSERT INTO accounts (email, password_hash, is_verified) "
		"VALUES ($1, $2, FALSE) RETURNING id;";
	pqxx::result result = tx.exec_params(sql, email, password_hash);
	tx.commit();

	int new_id = result[0][0].as<int>();
	std::cout << "Successfully created account with ID: " << new_id << std::endl;

	return true;
}

bool AccountManager::deleteAccount(const std::string& email, const std::string& password)
{
	return false;
}

bool AccountManager::doesAccountExist(const std::string& email)
{
	return false;
}

bool AccountManager::isEmailValid(const std::string& email)
{
	return false;
}

bool AccountManager::isPasswordSecure(const std::string& password)
{
	return false;
}

bool AccountManager::sendVerificationEmail(const std::string& emai)
{
	return false;
}

bool AccountManager::sendPasswordResetEmail(const std::string& email, const std::string& password)
{
	return false;
}

bool AccountManager::changePass(const std::string& email, const std::string& new_password)
{
	return false;
}

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
		std::cerr << "Error: Out of memory or another error occurred." << std::endl;
		return std::string();
	}
	hashed_password.resize(strlen(hashed_password.c_str()));
	return hashed_password;
}

bool AccountManager::verifyAccount(const std::string& email)
{
	return false;
}

bool AccountManager::isVerified(const std::string& email)
{
	return false;
}

bool AccountManager::tryLogin(const std::string& email, const std::string& password)
{
	return false;
}
