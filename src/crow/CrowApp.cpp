#include "CrowApp.h"

using traits = jwt::traits::kazuho_picojson;

CrowApp::CrowApp(AccountManager& accountManager) 
	:m_accountManager(accountManager)
{
}

void CrowApp::initializeRoutes()
{
	CROW_ROUTE(app, "/about")([]() {
		return "Hello world";
		});

	CROW_ROUTE(app, "/api/auth/register")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("email")) return crow::response(400, "Missing email");
			if (!json.has("password")) return crow::response(400, "Missing password");
			std::string email = json["email"].s();
			std::string password = json["password"].s();
			if (m_accountManager.doesAccountExist(email)) {
				return crow::response(409, "Email already exists");
			}
			if (!m_accountManager.isPasswordSecure(password)) {
				return crow::response(400, "Password is not secure");
			}
			if (m_accountManager.createAccount(email, password)) {
				return crow::response(201, "Account created successfully");
			} else {
				return crow::response(400, "Account creation failed");
			}
			});

	CROW_ROUTE(app, "/api/auth/login")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("email")) return crow::response(400, "Missing email");
			if (!json.has("password")) return crow::response(400, "Missing password");
			std::string email = json["email"].s();
			std::string password = json["password"].s();
			if (m_accountManager.tryLogIn(email, password)) {
				auto account_details = m_accountManager.getAccountDetails(email);
				
				picojson::array roles_array;
				roles_array.reserve(account_details->roles.size());
				for (const auto& role : account_details->roles) {
					roles_array.push_back(picojson::value(role));
				}

				std::string access_token = jwt::create<traits>()
					.set_issuer("keystone")
					.set_type("JWT")
					.set_payload_claim("user_id", picojson::value(static_cast<int64_t>(account_details->id)))
					.set_payload_claim("email", picojson::value(account_details->email))
					.set_payload_claim("roles", picojson::value(roles_array))
					.set_issued_now()
					.set_expires_in(std::chrono::seconds{ 15 * 60 })
					.sign(jwt::algorithm::hs256{ "secret" });

				std::string refresh_token = jwt::create<traits>()
					.set_issuer("keystone")
					.set_type("JWT")
					.set_payload_claim("user_id", picojson::value(static_cast<int64_t>(account_details->id)))
					.set_payload_claim("email", picojson::value(account_details->email))
					.set_payload_claim("roles", picojson::value(roles_array))
					.set_issued_now()
					.set_expires_in(std::chrono::seconds{ 24 * 60 * 60 * 7 })
					.sign(jwt::algorithm::hs256{ "secret" });

				std::string refresh_token_hash = m_accountManager.hash_token(refresh_token);
				m_accountManager.storeRefreshTokenHash(account_details->id, refresh_token_hash);

				return crow::response(200, crow::json::wvalue({
					{"access_token", access_token},
					{"refresh_token", refresh_token}
				}));

			} else {
				return crow::response(401, "Invalid credentials");
			}
			});
	CROW_ROUTE(app, "/api/auth/refresh")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			std::string refresh_token = json["refresh_token"].s();
			try {
				auto verifier = jwt::verify<traits>()
					.with_issuer("keystone")
					.allow_algorithm(jwt::algorithm::hs256{ "secret" });
				auto decoded_token = jwt::decode<traits>(refresh_token);
				verifier.verify(decoded_token);

				int user_id = decoded_token.get_payload_claim("user_id").as_integer();
				std::string stored_hash = m_accountManager.getRefreshTokenHash(user_id).value_or("");
				if (m_accountManager.hash_token(refresh_token) != stored_hash) {
					return crow::response(401, "Invalid refresh token");
				}

				auto email = decoded_token.get_payload_claim("email").as_string();
				auto roles_claim = decoded_token.get_payload_claim("roles").as_array();
				
				std::string new_access_token = jwt::create<traits>()
					.set_issuer("keystone")
					.set_type("JWT")
					.set_payload_claim("user_id", picojson::value(static_cast<int64_t>(user_id)))
					.set_payload_claim("email", picojson::value(email))
					.set_payload_claim("roles", picojson::value(roles_claim))
					.set_issued_now()
					.set_expires_in(std::chrono::seconds{ 15 * 60 })
					.sign(jwt::algorithm::hs256{ "secret" });
				return crow::response(200, crow::json::wvalue({
					{"access_token", new_access_token}
				}));
			} catch (const std::exception& e) {
				return crow::response(401, "Invalid refresh token");
			}
			});
	CROW_ROUTE(app, "/api/auth/logout")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			std::string refresh_token = json["refresh_token"].s();
			try {
				auto decoded_token = jwt::decode<traits>(refresh_token);
				auto verifier = jwt::verify<traits>()
					.with_issuer("keystone")
					.allow_algorithm(jwt::algorithm::hs256{ "secret" });
				verifier.verify(decoded_token);

				int user_id = decoded_token.get_payload_claim("user_id").as_integer();

				if (m_accountManager.deleteRefreshTokenHash(user_id)) {
					return crow::response(200, "Logged out successfully");
				} else {
					return crow::response(500, "Failed to log out");
				}
			} catch (const std::exception& e) {
				return crow::response(401, "Invalid refresh token");
			}
			});

}

void CrowApp::run(int port)
{
	app.port(port).multithreaded().run();
}
