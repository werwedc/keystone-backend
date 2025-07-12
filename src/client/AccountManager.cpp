#include "AccountManager.h"
#include <vector>
#include <string>
#include <sodium.h>
#include <cctype> 

AccountManager::AccountManager(pqxx::connection& db_connection)
	: m_db_connection(db_connection) 
{
}

bool AccountManager::createAccount(const std::string& email, const std::string& password)
{
	try {
		std::string password_hash = hash_password(password);

		pqxx::work tx(m_db_connection);
		std::string sql = "INSERT INTO accounts (email, password_hash, is_verified) "
			"VALUES ($1, $2, FALSE) RETURNING id;";

		pqxx::result result = tx.exec_params(sql, email, password_hash);
		tx.commit();

		if (!result.empty()) {
			int new_id = result[0][0].as<int>();
			std::cout << "Successfully created account with ID: " << new_id << std::endl;
			return true;
		}
		else {
			return false;
		}

	}
	catch (const std::exception& e) {
		std::cerr << "Error while creating account: " << e.what() << std::endl;
		return false;
	}
}

bool AccountManager::deleteAccount(const std::string& email)
{
	try {
		pqxx::work tx(m_db_connection);
		std::string sql = "DELETE FROM accounts WHERE LOWER(email) = LOWER($1);";

		pqxx::result result = tx.exec_params(sql, email);
		tx.commit();
		return result.affected_rows() > 0;
	}
	catch (const std::exception& e) {
		std::cerr << "Error while deleting account: " << e.what() << std::endl;
		return false;
	}
}

bool AccountManager::doesAccountExist(const std::string& email)
{
	try {
		pqxx::read_transaction tx(m_db_connection);
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

bool AccountManager::changePass(const std::string& email, const std::string& new_password){
	try {
		std::string new_hash = hash_password(new_password);
		pqxx::work tx(m_db_connection);
		std::string sql = "UPDATE accounts SET password_hash = $1 WHERE LOWER(email) = LOWER($2);";
		pqxx::result result = tx.exec_params(sql, new_hash, email);
		tx.commit();
		return result.affected_rows() > 0;
	}
	catch (const std::exception& e) {
		std::cerr << "Error while chenging password: " << e.what() << std::endl;
	}
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



bool AccountManager::tryLogIn(const std::string& email, const std::string& password_attempt) {
	std::string stored_hash;

	// To prevent timing attacks
	std::string fake_hash = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$R+IM63_d5t41p1_a25DRRgn92XD3ZvoKx2fC2hddMAo";
	try {
		pqxx::read_transaction tx(m_db_connection);
		std::string sql = "SELECT password_hash FROM accounts WHERE LOWER(email) = LOWER($1);";
		pqxx::result result = tx.exec_params(sql, email);

		if (!result.empty()) {
			stored_hash = result[0][0].as<std::string>();
		} else {
			stored_hash = fake_hash;
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
