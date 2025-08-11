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
			// Parse and validate JSON body
			const auto body = crow::json::load(req.body);
			if (!body) {
				return crow::response(400, "Invalid JSON payload");
			}

			// Extract required fields
			if (!body.has("email") || !body.has("password")) {
				return crow::response(400, "Missing required fields: email and/or password");
			}
			const std::string email = body["email"].s();
			const std::string password = body["password"].s();

			// Business logic checks
			if (m_accountManager.doesAccountExist(email)) {
				return crow::response(409, "Email already exists");
			}
			if (!m_accountManager.isPasswordSecure(password)) {
				return crow::response(400, "Password is not secure");
			}

			// Create account
			return m_accountManager.createAccount(email, password)
				? crow::response(201, "Account created successfully")
				: crow::response(400, "Account creation failed");
		});

	CROW_ROUTE(app, "/api/auth/login")
		.methods("POST"_method)
		([this](const crow::request& req) {
			// Parse and validate request JSON
			auto json = crow::json::load(req.body);
			if (!json) return crow::response(400, "Invalid JSON");
			if (!json.has("email")) return crow::response(400, "Missing email");
			if (!json.has("password")) return crow::response(400, "Missing password");

			const std::string email = json["email"].s();
			const std::string password = json["password"].s();

			// Authenticate user
			if (!m_accountManager.tryLogIn(email, password)) {
				return crow::response(401, "Invalid credentials");
			}

			// Retrieve account details
			auto account = m_accountManager.getAccountDetails(email);

			// Build roles array
			picojson::array roles_array;
			roles_array.reserve(account->roles.size());
			for (const auto& role : account->roles) {
				roles_array.emplace_back(role);
			}

			auto make_token = [&](std::chrono::seconds ttl) {
				return jwt::create<traits>()
					.set_issuer("keystone")
					.set_type("JWT")
					.set_payload_claim("user_id", picojson::value(static_cast<int64_t>(account->id)))
					.set_payload_claim("email", picojson::value(account->email))
					.set_payload_claim("roles", picojson::value(roles_array))
					.set_issued_now()
					.set_expires_in(ttl)
					.sign(jwt::algorithm::hs256{"secret"});
			};

			// Generate tokens
			std::string access_token  = make_token(std::chrono::seconds{15 * 60});
			std::string refresh_token = make_token(std::chrono::seconds{24 * 60 * 60 * 7});

			// Store refresh token hash
			m_accountManager.storeRefreshTokenHash(account->id, m_accountManager.hash_token(refresh_token));

			// Return response
			return crow::response(200, crow::json::wvalue({
				{"access_token",  access_token},
				{"refresh_token", refresh_token}
			}));
	});

	CROW_ROUTE(app, "/api/auth/refresh")
		.methods("POST"_method)
		([this](const crow::request& req) {
		    // Parse request body
		    auto json = crow::json::load(req.body);
		    if (!json) return crow::response(400, "Invalid JSON");
		    if (!json.has("refresh_token")) return crow::response(400, "Missing refresh token");

		    const std::string refresh_token = json["refresh_token"].s();

		    try {
		        // Verify and decode refresh token
		        auto verifier = jwt::verify<traits>()
		            .with_issuer("keystone")
		            .allow_algorithm(jwt::algorithm::hs256{"secret"});

		        auto decoded = jwt::decode<traits>(refresh_token);
		        verifier.verify(decoded);

		        // Validate token against stored hash
		        const int user_id = decoded.get_payload_claim("user_id").as_integer();
		        auto stored_hash_opt = m_accountManager.getRefreshTokenHash(user_id);
		        if (!stored_hash_opt.has_value() ||
		            m_accountManager.hash_token(refresh_token) != stored_hash_opt.value()) {
		            return crow::response(401, "Invalid refresh token");
		        }

		        // Extract claims
		        const std::string email = decoded.get_payload_claim("email").as_string();
		        const auto roles_claim = decoded.get_payload_claim("roles").as_array();

		        // Helper to create access token
		        auto make_access_token = [&](std::chrono::seconds ttl) {
		            return jwt::create<traits>()
		                .set_issuer("keystone")
		                .set_type("JWT")
		                .set_payload_claim("user_id", picojson::value(static_cast<int64_t>(user_id)))
		                .set_payload_claim("email", picojson::value(email))
		                .set_payload_claim("roles", picojson::value(roles_claim))
		                .set_issued_now()
		                .set_expires_in(ttl)
		                .sign(jwt::algorithm::hs256{"secret"});
		        };

		        // Generate new short-lived access token
		        std::string new_access_token = make_access_token(std::chrono::seconds{15 * 60});

		        return crow::response(200, crow::json::wvalue({
		            {"access_token", new_access_token}
		        }));

		    } catch (const std::exception&) {
		        return crow::response(401, "Invalid refresh token");
		    }
		});

	CROW_ROUTE(app, "/api/auth/logout")
		.methods("POST"_method)
		([this](const crow::request& req) {
			// Parse request body
			auto json = crow::json::load(req.body);
			if (!json) return crow::response(400, "Invalid JSON");
			if (!json.has("refresh_token")) return crow::response(400, "Missing refresh token");

			const std::string refresh_token = json["refresh_token"].s();

			try {
				// Decode and verify token
				auto decoded = jwt::decode<traits>(refresh_token);
				jwt::verify<traits>()
					.with_issuer("keystone")
					.allow_algorithm(jwt::algorithm::hs256{"secret"})
					.verify(decoded);

				// Extract user ID
				const int user_id = decoded.get_payload_claim("user_id").as_integer();

				// Delete stored refresh token hash
				if (m_accountManager.deleteRefreshTokenHash(user_id)) {
					return crow::response(200, "Logged out successfully");
				}
				return crow::response(500, "Failed to log out");

			} catch (const std::exception&) {
				return crow::response(401, "Invalid refresh token");
			}
		});

	CROW_ROUTE(app, "/api/applications/create")
	.methods("POST"_method)
	([this](const crow::request& req) {
		auto json = crow::json::load(req.body);
		if (!json) return crow::response(400, "Invalid JSON");
		if (!json.has("name")) return crow::response(400, "Missing name");
		if (!json.has("access_token")) return crow::response(400, "Missing access token");

		const std::string name = json["name"].s();
		const std::string access_token = json["access_token"].s();

		auto user_id = verifyAccessTokenAndGetUserID(access_token);
		if (!user_id) return crow::response(401, "Invalid access token");

		if (m_applicationsManager.createApplication(*user_id, name)) {
			return crow::response(200, "Application created successfully");
		}
		return crow::response(500, "Failed to create application");
	});

	CROW_ROUTE(app, "/api/applications/delete")
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

			// Verify token and get user ID
			auto user_id = verifyAccessTokenAndGetUserID(access_token);
			if (!user_id) {
				return crow::response(401, "Invalid access token");
			}

			// Get application details
			auto appDetailsOpt = m_applicationsManager.getApplication(application_id);
			if (!appDetailsOpt) {
				return crow::response(404, "Application not found");
			}

			const auto& appDetails = *appDetailsOpt;

			// Ownership check
			if (appDetails.user_id != *user_id) {
				return crow::response(403, "You do not own this application");
			}

			// Delete application
			if (m_applicationsManager.deleteApplication(application_id)) {
				return crow::response(200, "Application deleted successfully");
			} else {
				return crow::response(500, "Failed to delete application");
			}
		});

	CROW_ROUTE(app, "/api/applications/set_active")
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

			// Verify token and get user ID
			auto user_id = verifyAccessTokenAndGetUserID(access_token);
			if (!user_id) {
				return crow::response(401, "Invalid access token");
			}

			// Get application details
			auto appDetailsOpt = m_applicationsManager.getApplication(application_id);
			if (!appDetailsOpt) {
				return crow::response(404, "Application not found");
			}

			const auto& appDetails = *appDetailsOpt;

			// Ownership check
			if (appDetails.user_id != *user_id) {
				return crow::response(403, "You do not own this application");
			}

			// Update active status
			if (m_applicationsManager.setActive(application_id, active)) {
				return crow::response(200, "Application active status updated successfully");
			} else {
				return crow::response(500, "Failed to update application active status");
			}
		});

	CROW_ROUTE(app, "/api/applications/rename")
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

			// Verify token and extract user ID
			auto user_id = verifyAccessTokenAndGetUserID(access_token);
			if (!user_id) {
				return crow::response(401, "Invalid access token");
			}

			// Get application details
			auto appDetailsOpt = m_applicationsManager.getApplication(application_id);
			if (!appDetailsOpt) {
				return crow::response(404, "Application not found");
			}

			const auto& appDetails = *appDetailsOpt;

			// Check ownership
			if (appDetails.user_id != *user_id) {
				return crow::response(403, "You do not own this application");
			}

			// Rename application
			if (m_applicationsManager.renameApplication(application_id, name)) {
				return crow::response(200, "Application renamed successfully");
			} else {
				return crow::response(500, "Failed to rename application");
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

			// Verify token and get user ID
			auto user_id = verifyAccessTokenAndGetUserID(access_token);
			if (!user_id) {
				return crow::response(401, "Invalid access token");
			}

			// Get all applications for this user
			std::vector<ApplicationDetails> applications = m_applicationsManager.getApplications(*user_id);

			// Prepare JSON response
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
		});


}

void CrowApp::run(int port)
{
	app.port(port).multithreaded().run();
}

std::optional<int> CrowApp::verifyAccessTokenAndGetUserID(const std::string &accessToken) {
	try {
		auto decoded = jwt::decode<traits>(accessToken);
		jwt::verify<traits>()
			.with_issuer("keystone")
			.allow_algorithm(jwt::algorithm::hs256{"secret"})
			.verify(decoded);

		return decoded.get_payload_claim("user_id").as_integer();
	} catch (...) {
		return std::nullopt;
	}
}
