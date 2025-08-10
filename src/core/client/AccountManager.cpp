#include "AccountManager.h"

AccountManager::AccountManager(DatabaseManager& db_manager)
	: m_db_manager(db_manager)
{
}

bool AccountManager::createAccount(const std::string& email, const std::string& password)
{
	try {
		std::string password_hash = hash_password(password);

		pqxx::work tx(*m_db_manager.getConnection());
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

bool AccountManager::deleteAccount(int id)
{
	try {
		pqxx::work tx(*m_db_manager.getConnection());
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

bool AccountManager::doesAccountExist(const std::string& email)
{
	try {
		pqxx::read_transaction tx(*m_db_manager.getConnection());
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

bool AccountManager::changePass(int id, const std::string& new_password){
	try {
		std::string new_hash = hash_password(new_password);
		pqxx::work tx(*m_db_manager.getConnection());
		std::string sql = "UPDATE accounts SET password_hash = $1 WHERE id = $2;";
		pqxx::result result = tx.exec_params(sql, new_hash, id);
		tx.commit();
		return result.affected_rows() > 0;
	}
	catch (const std::exception& e) {
		std::cerr << "Error while chenging password: " << e.what() << std::endl;
		return false;
	}
}

bool AccountManager::tryLogIn(const std::string& email, const std::string& password_attempt) {
	std::string stored_hash;

	// To prevent timing attacks
	std::string fake_hash = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$R+IM63_d5t41p1_a25DRRgn92XD3ZvoKx2fC2hddMAo";
	try {
		pqxx::read_transaction tx(*m_db_manager.getConnection());
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

std::optional<AccountDetails> AccountManager::getAccountDetails(const std::string& email)
{
	AccountDetails account_details{};
	try
	{
		pqxx::read_transaction tx(*m_db_manager.getConnection());
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

bool AccountManager::storeRefreshTokenHash(int user_id, const std::string& refresh_token_hash)
{
	try {
		pqxx::work tx(*m_db_manager.getConnection());
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

std::optional<std::string> AccountManager::getRefreshTokenHash(int user_id)
{
	try
	{
		pqxx::read_transaction tx(*m_db_manager.getConnection());
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

bool AccountManager::deleteRefreshTokenHash(int user_id)
{
	try {
		pqxx::work tx(*m_db_manager.getConnection());
		std::string sql = "UPDATE accounts "
			"SET refresh_token_hash = NULL "
			"WHERE id = $1;";

		pqxx::result result = tx.exec_params(sql, user_id);
		tx.commit();

		return result.affected_rows() > 0;
	}
	catch (const std::exception& e) {
		std::cerr << "Error while deliting refresh token hash: " << e.what() << std::endl;
		return false;
	}
}

std::string AccountManager::hash_token(const std::string& token)
{
	unsigned char hash[crypto_hash_sha256_BYTES];
	crypto_hash_sha256(
		hash,
		reinterpret_cast<const unsigned char*>(token.c_str()),
		token.length()
	);
	std::string hex_hash = bytes_to_hex(hash, sizeof(hash));
	
	return hex_hash;
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

std::vector<std::string> AccountManager::parsePgTextArray(const std::string& pg_array_string)
{	
	std::vector<std::string> vec;
	vec.clear();

	bool is_writing = false;
	for (char c : pg_array_string) {
		std::string char_string {c};
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

std::string AccountManager::bytes_to_hex(const unsigned char* bytes, size_t len)
{
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (size_t i = 0; i < len; ++i) {
		ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
	}
	return ss.str();
}
