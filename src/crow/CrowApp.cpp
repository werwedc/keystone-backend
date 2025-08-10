#include "CrowApp.h"

using traits = jwt::traits::kazuho_picojson;

CrowApp::CrowApp(AccountManager& accountManager, ApplicationsManager& applicationsManager)
	:m_accountManager(accountManager), m_applicationsManager(applicationsManager)
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
	// Applications
	CROW_ROUTE(app, "/api/applications/create")
		.methods("POST"_method)
			([this](const crow::request& req) {
				auto json = crow::json::load(req.body);
				if (!json) {
					return crow::response(400, "Invalid JSON");
				}
				if (!json.has("name")) return crow::response(400, "Missing name");
				if (!json.has("access_token")) return crow::response(400, "Missing access token");
				std::string access_token = json["access_token"].s();
				std::string name = json["name"].s();
				try {
					auto decoded_token = jwt::decode<traits>(access_token);
					auto verifier = jwt::verify<traits>()
						.with_issuer("keystone")
						.allow_algorithm(jwt::algorithm::hs256{ "secret"});
					verifier.verify(decoded_token);

					int user_id = decoded_token.get_payload_claim("user_id").as_integer();

					if (m_applicationsManager.createApplication(user_id, name)) {
						return crow::response(200, "Application created successfully");
					} else {
						return crow::response(500, "Failed to create application");
					}
				} catch (const std::exception& e) {
					return crow::response(401, "Invalid access token");
				}
			});
	CROW_ROUTE(app, "/api/application/delete")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("application_id")) return crow::response(400, "Missing application_id");
			if (!json.has("access_token")) return crow::response(400, "Missing access token");
			std::string access_token = json["access_token"].s();
			int application_id = json["application_id"].i();
			try {
				auto decoded_token = jwt::decode<traits>(access_token);
				auto verifier = jwt::verify<traits>()
					.with_issuer("keystone")
					.allow_algorithm(jwt::algorithm::hs256{ "secret" });
				verifier.verify(decoded_token);

				if (m_applicationsManager.deleteApplication(application_id)) {
					return crow::response(200, "Application deleted successfully");
				} else {
					return crow::response(500, "Failed to delete application");
				}
			} catch (const std::exception& e) {
				return crow::response(401, "Invalid access token");
			}
			});
	CROW_ROUTE(app, "/api/application/set_active")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("application_id")) return crow::response(400, "Missing application_id");
			if (!json.has("active")) return crow::response(400, "Missing active status");
			if (!json.has("access_token")) return crow::response(400, "Missing access token");
			std::string access_token = json["access_token"].s();
			int application_id = json["application_id"].i();
			bool active = json["active"].b();
			try {
				auto decoded_token = jwt::decode<traits>(access_token);
				auto verifier = jwt::verify<traits>()
					.with_issuer("keystone")
					.allow_algorithm(jwt::algorithm::hs256{ "secret" });
				verifier.verify(decoded_token);

				if (m_applicationsManager.setActive(application_id, active)) {
					return crow::response(200, "Application active status updated successfully");
				} else {
					return crow::response(500, "Failed to update application active status");
				}
			} catch (const std::exception& e) {
				return crow::response(401, "Invalid access token");
			}
			});
	CROW_ROUTE(app, "/api/application/rename")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("application_id")) return crow::response(400, "Missing application_id");
			if (!json.has("name")) return crow::response(400, "Missing new name");
			if (!json.has("access_token")) return crow::response(400, "Missing access token");
			std::string access_token = json["access_token"].s();
			int application_id = json["application_id"].i();
			std::string name = json["name"].s();
			try {
				auto decoded_token = jwt::decode<traits>(access_token);
				auto verifier = jwt::verify<traits>()
					.with_issuer("keystone")
					.allow_algorithm(jwt::algorithm::hs256{ "secret" });
				verifier.verify(decoded_token);

				if (m_applicationsManager.renameApplication(application_id, name)) {
					return crow::response(200, "Application renamed successfully");
				} else {
					return crow::response(500, "Failed to rename application");
				}
			} catch (const std::exception&e) {
				return crow::response(401, "Invalid access token");
			}
			});
	CROW_ROUTE(app, "/api/applications/get_all")
		.methods("POST"_method)
		([this](const crow::request& req) {
			auto json = crow::json::load(req.body);
			if (!json) {
				return crow::response(400, "Invalid JSON");
			}
			if (!json.has("access_token")) return crow::response(400, "Missing access token");
			std::string access_token = json["access_token"].s();
			try {
				auto decoded_token = jwt::decode<traits>(access_token);
				auto verifier = jwt::verify<traits>()
					.with_issuer("keystone")
					.allow_algorithm(jwt::algorithm::hs256{ "secret" });
				verifier.verify(decoded_token);

				int user_id = decoded_token.get_payload_claim("user_id").as_integer();
				std::vector<ApplicationDetails> applications = m_applicationsManager.getApplications(user_id);

				crow::json::wvalue response_json;
				crow::json::wvalue::list applications_list;
				for (const auto& app_details : applications) {
					applications_list.emplace_back(crow::json::wvalue({
						{"id", app_details.id},
						{"user_id", app_details.user_id},
						{"name", app_details.name},
						{"active", app_details.active}
					}));
				}
				response_json["applications"] = std::move(applications_list);
				return crow::response(200, response_json);
			} catch (const std::exception& e) {
				return crow::response(401, "Invalid access token");
			}
			});

}

void CrowApp::run(int port)
{
	app.port(port).multithreaded().run();
}
