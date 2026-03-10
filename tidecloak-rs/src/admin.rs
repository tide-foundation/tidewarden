use crate::error::{Result, TideCloakError};
use crate::types::TideCloakConfig;

/// REST client for TideCloak admin API endpoints.
///
/// Wraps common admin operations like user management, role management, etc.
/// Requires an access token with appropriate admin roles.
pub struct AdminClient {
    config: TideCloakConfig,
    http: reqwest::Client,
    access_token: String,
}

impl AdminClient {
    pub fn new(config: TideCloakConfig, access_token: String) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
            access_token,
        }
    }

    /// Create an AdminClient from just a base URL, realm, and token.
    /// Useful when you don't have a full TideCloakConfig (e.g. in server-side proxies).
    pub fn from_url(base_url: &str, realm: &str, access_token: &str) -> Self {
        let config = TideCloakConfig {
            auth_server_url: base_url.to_string(),
            realm: realm.to_string(),
            resource: String::new(),
            scope: None,
            vendor_id: None,
            home_ork_url: None,
            auth_mode: "native".to_string(),
            use_dpop: None,
        };
        Self {
            config,
            http: reqwest::Client::new(),
            access_token: access_token.to_string(),
        }
    }

    /// Update the access token (e.g., after refresh)
    pub fn set_access_token(&mut self, token: String) {
        self.access_token = token;
    }

    /// Get the base URL (auth_server_url without trailing slash)
    pub fn base_url(&self) -> &str {
        self.config.auth_server_url.trim_end_matches('/')
    }

    /// Get the realm name
    pub fn realm(&self) -> &str {
        &self.config.realm
    }

    fn admin_base(&self) -> String {
        let base = self.base_url();
        format!("{base}/admin/realms/{}", self.config.realm)
    }

    fn realm_base(&self) -> String {
        let base = self.base_url();
        format!("{base}/realms/{}", self.config.realm)
    }

    // ---- Low-level HTTP helpers ----

    async fn get(&self, url: &str) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.access_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Admin API GET failed ({status}): {body}"
            )));
        }
        Ok(resp.json().await?)
    }

    #[allow(dead_code)]
    async fn get_text(&self, url: &str) -> Result<String> {
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.access_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Admin API GET failed ({status}): {body}"
            )));
        }
        Ok(resp.text().await?)
    }

    /// GET without auth (for public endpoints)
    async fn get_public(&self, url: &str) -> Result<serde_json::Value> {
        let resp = self.http.get(url).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Public GET failed ({status}): {body}"
            )));
        }
        Ok(resp.json().await?)
    }

    /// GET public text response
    async fn get_public_text(&self, url: &str) -> Result<String> {
        let resp = self.http.get(url).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Public GET failed ({status}): {body}"
            )));
        }
        Ok(resp.text().await?)
    }

    async fn post(&self, url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.access_token)
            .json(body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Admin API POST failed ({status}): {text}"
            )));
        }

        let text = resp.text().await.unwrap_or_default();
        if text.is_empty() {
            Ok(serde_json::Value::Null)
        } else {
            Ok(serde_json::from_str(&text)?)
        }
    }

    /// POST with form-encoded body (for TideCloak endpoints that expect form data)
    #[allow(dead_code)]
    async fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<String> {
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.access_token)
            .form(params)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Admin API POST form failed ({status}): {text}"
            )));
        }
        Ok(resp.text().await.unwrap_or_default())
    }

    /// POST with form params that can have repeated keys (e.g. multiple "requests" values)
    async fn post_form_multi(&self, url: &str, params: &[(&str, String)]) -> Result<String> {
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.access_token)
            .form(params)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Admin API POST form failed ({status}): {text}"
            )));
        }
        Ok(resp.text().await.unwrap_or_default())
    }

    async fn delete(&self, url: &str) -> Result<()> {
        let resp = self
            .http
            .delete(url)
            .bearer_auth(&self.access_token)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Admin API DELETE failed ({status}): {body}"
            )));
        }
        Ok(())
    }

    /// DELETE with a JSON body (e.g. for removing role mappings)
    async fn delete_with_body(&self, url: &str, body: &serde_json::Value) -> Result<()> {
        let resp = self
            .http
            .delete(url)
            .bearer_auth(&self.access_token)
            .json(body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Admin API DELETE failed ({status}): {text}"
            )));
        }
        Ok(())
    }

    async fn put(&self, url: &str, body: &serde_json::Value) -> Result<()> {
        let resp = self
            .http
            .put(url)
            .bearer_auth(&self.access_token)
            .json(body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Admin API PUT failed ({status}): {text}"
            )));
        }
        Ok(())
    }

    // ---- User management ----

    /// Get all users in the realm
    pub async fn get_users(&self) -> Result<serde_json::Value> {
        self.get(&format!("{}/users", self.admin_base())).await
    }

    /// Get a user by ID
    pub async fn get_user(&self, user_id: &str) -> Result<serde_json::Value> {
        self.get(&format!("{}/users/{}", self.admin_base(), user_id))
            .await
    }

    /// Search users by email (exact match)
    pub async fn search_users_by_email(&self, email: &str) -> Result<Vec<serde_json::Value>> {
        let encoded = urlencoding::encode(email);
        let url = format!("{}/users?email={}&exact=true", self.admin_base(), encoded);
        let val = self.get(&url).await?;
        Ok(serde_json::from_value(val).unwrap_or_default())
    }

    /// Search users by username (exact match)
    pub async fn search_users_by_username(&self, username: &str) -> Result<Vec<serde_json::Value>> {
        let encoded = urlencoding::encode(username);
        let url = format!("{}/users?username={}&exact=true", self.admin_base(), encoded);
        let val = self.get(&url).await?;
        Ok(serde_json::from_value(val).unwrap_or_default())
    }

    /// Create a new user
    pub async fn create_user(&self, user_data: &serde_json::Value) -> Result<serde_json::Value> {
        self.post(&format!("{}/users", self.admin_base()), user_data)
            .await
    }

    /// Delete a user
    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        self.delete(&format!("{}/users/{}", self.admin_base(), user_id))
            .await
    }

    /// Update a user
    pub async fn update_user(
        &self,
        user_id: &str,
        user_data: &serde_json::Value,
    ) -> Result<()> {
        self.put(
            &format!("{}/users/{}", self.admin_base(), user_id),
            user_data,
        )
        .await
    }

    // ---- Role management ----

    /// Get all realm roles
    pub async fn get_realm_roles(&self) -> Result<serde_json::Value> {
        self.get(&format!("{}/roles", self.admin_base())).await
    }

    /// Get a realm role by name
    pub async fn get_realm_role(&self, role_name: &str) -> Result<serde_json::Value> {
        self.get(&format!("{}/roles/{}", self.admin_base(), role_name))
            .await
    }

    /// Get roles assigned to a user
    pub async fn get_user_realm_roles(&self, user_id: &str) -> Result<serde_json::Value> {
        self.get(&format!(
            "{}/users/{}/role-mappings/realm",
            self.admin_base(),
            user_id
        ))
        .await
    }

    /// Assign realm roles to a user
    pub async fn assign_realm_roles(
        &self,
        user_id: &str,
        roles: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.post(
            &format!(
                "{}/users/{}/role-mappings/realm",
                self.admin_base(),
                user_id
            ),
            roles,
        )
        .await
    }

    /// Remove realm roles from a user
    pub async fn remove_realm_roles(&self, user_id: &str, roles: &serde_json::Value) -> Result<()> {
        self.delete_with_body(
            &format!(
                "{}/users/{}/role-mappings/realm",
                self.admin_base(),
                user_id
            ),
            roles,
        )
        .await
    }

    // ---- Client management ----

    /// Get all clients in the realm
    pub async fn get_clients(&self) -> Result<serde_json::Value> {
        self.get(&format!("{}/clients", self.admin_base())).await
    }

    /// Get a client by internal UUID
    pub async fn get_client(&self, client_id: &str) -> Result<serde_json::Value> {
        self.get(&format!("{}/clients/{}", self.admin_base(), client_id))
            .await
    }

    /// Find a client by its human-readable clientId. Returns the internal UUID.
    pub async fn find_client_uuid(&self, client_id: &str) -> Result<String> {
        let encoded = urlencoding::encode(client_id);
        let url = format!("{}/clients?clientId={}", self.admin_base(), encoded);
        let val = self.get(&url).await?;
        let clients: Vec<serde_json::Value> = serde_json::from_value(val).unwrap_or_default();
        clients
            .first()
            .and_then(|c| c.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| TideCloakError::Auth(format!("Client '{client_id}' not found")))
    }

    // ---- Client role management ----

    /// List all roles for a client
    pub async fn get_client_roles(&self, client_uuid: &str) -> Result<serde_json::Value> {
        self.get(&format!(
            "{}/clients/{}/roles",
            self.admin_base(),
            client_uuid
        ))
        .await
    }

    /// Get a specific client role by name
    pub async fn get_client_role(&self, client_uuid: &str, role_name: &str) -> Result<serde_json::Value> {
        self.get(&format!(
            "{}/clients/{}/roles/{}",
            self.admin_base(),
            client_uuid,
            role_name
        ))
        .await
    }

    /// Create a client role
    pub async fn create_client_role(
        &self,
        client_uuid: &str,
        role_data: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.post(
            &format!("{}/clients/{}/roles", self.admin_base(), client_uuid),
            role_data,
        )
        .await
    }

    /// Delete a client role by name
    pub async fn delete_client_role(&self, client_uuid: &str, role_name: &str) -> Result<()> {
        self.delete(&format!(
            "{}/clients/{}/roles/{}",
            self.admin_base(),
            client_uuid,
            role_name
        ))
        .await
    }

    /// Get a user's client role mappings
    pub async fn get_user_client_roles(
        &self,
        user_id: &str,
        client_uuid: &str,
    ) -> Result<serde_json::Value> {
        self.get(&format!(
            "{}/users/{}/role-mappings/clients/{}",
            self.admin_base(),
            user_id,
            client_uuid
        ))
        .await
    }

    /// Assign client roles to a user
    pub async fn assign_user_client_roles(
        &self,
        user_id: &str,
        client_uuid: &str,
        roles: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.post(
            &format!(
                "{}/users/{}/role-mappings/clients/{}",
                self.admin_base(),
                user_id,
                client_uuid
            ),
            roles,
        )
        .await
    }

    /// Remove client roles from a user
    pub async fn remove_user_client_roles(
        &self,
        user_id: &str,
        client_uuid: &str,
        roles: &serde_json::Value,
    ) -> Result<()> {
        self.delete_with_body(
            &format!(
                "{}/users/{}/role-mappings/clients/{}",
                self.admin_base(),
                user_id,
                client_uuid
            ),
            roles,
        )
        .await
    }

    /// Add composite (child) roles to a parent role by the parent's UUID.
    pub async fn add_composite_roles(
        &self,
        parent_role_id: &str,
        children: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.post(
            &format!(
                "{}/roles-by-id/{}/composites",
                self.admin_base(),
                parent_role_id
            ),
            children,
        )
        .await
    }

    /// Add a role as a default role for the realm (composite of default-roles-{realm})
    pub async fn add_default_role(&self, role: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!(
            "{}/roles/default-roles-{}/composites",
            self.admin_base(),
            self.config.realm
        );
        self.post(&url, &serde_json::json!([role])).await
    }

    // ---- Realm info ----

    /// Get realm info
    pub async fn get_realm(&self) -> Result<serde_json::Value> {
        self.get(&self.admin_base()).await
    }

    // ---- TideCloak Tide-Admin endpoints ----

    /// List pending change requests by entity type ("users", "roles", or "clients")
    pub async fn tide_list_change_requests(&self, entity_type: &str) -> Result<serde_json::Value> {
        self.get(&format!(
            "{}/tide-admin/change-set/{}/requests",
            self.admin_base(),
            entity_type
        ))
        .await
    }

    /// Sign (approve) a change request
    pub async fn tide_sign_change_request(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post(
            &format!("{}/tide-admin/change-set/sign", self.admin_base()),
            body,
        )
        .await
    }

    /// Commit a change request
    pub async fn tide_commit_change_request(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post(
            &format!("{}/tide-admin/change-set/commit", self.admin_base()),
            body,
        )
        .await
    }

    /// Cancel a change request
    pub async fn tide_cancel_change_request(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post(
            &format!("{}/tide-admin/change-set/cancel", self.admin_base()),
            body,
        )
        .await
    }

    /// Submit an approval (add-review) — uses form encoding with repeatable "requests" param.
    pub async fn tide_add_review(&self, params: &[(&str, String)]) -> Result<String> {
        let url = format!(
            "{}/tideAdminResources/add-review",
            self.admin_base()
        );
        self.post_form_multi(&url, params).await
    }

    /// Submit a rejection — uses form encoding.
    pub async fn tide_add_rejection(&self, params: &[(&str, String)]) -> Result<String> {
        let url = format!(
            "{}/tideAdminResources/add-rejection",
            self.admin_base()
        );
        self.post_form_multi(&url, params).await
    }

    /// Get a user's committed UserContext + VVK signature by userId and clientId.
    pub async fn tide_get_user_context(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<serde_json::Value> {
        self.get(&format!(
            "{}/tide-admin/user-context/{}/{}",
            self.admin_base(),
            user_id,
            client_id
        ))
        .await
    }

    /// Get a user's committed UserContext by changeSetId.
    pub async fn tide_get_user_context_by_change_set(
        &self,
        change_set_id: &str,
    ) -> Result<serde_json::Value> {
        self.get(&format!(
            "{}/tide-admin/change-set/{}/user-context",
            self.admin_base(),
            change_set_id
        ))
        .await
    }

    /// Store a committed policy (initCert) on a role's TideRoleDraftEntity.
    pub async fn tide_set_role_init_cert(
        &self,
        role_id: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.post(
            &format!(
                "{}/tide-admin/role-policy/{}/init-cert",
                self.admin_base(),
                role_id
            ),
            body,
        )
        .await
    }

    /// Fetch the admin policy from TideCloak's public endpoint (no auth required).
    /// Returns base64-encoded admin policy bytes.
    pub async fn tide_get_admin_policy(&self) -> Result<String> {
        let url = format!(
            "{}/tide-policy-resources/admin-policy",
            self.realm_base()
        );
        self.get_public_text(&url).await
    }

    /// Fetch the VVK public key from TideCloak's public endpoint (no auth required).
    pub async fn tide_get_vvk_public(&self) -> Result<serde_json::Value> {
        let url = format!(
            "{}/tide-policy-resources/vvk-public",
            self.realm_base()
        );
        self.get_public(&url).await
    }

    /// Get a required-action link (e.g. link-tide-account-action) for a user.
    pub async fn tide_get_action_link(
        &self,
        user_id: &str,
        client_id: &str,
        redirect_uri: &str,
        lifespan: u64,
        actions: &[&str],
    ) -> Result<String> {
        let encoded_redirect = urlencoding::encode(redirect_uri);
        let encoded_client = urlencoding::encode(client_id);
        let url = format!(
            "{}/tideAdminResources/get-required-action-link?userId={}&lifespan={}&redirect_uri={}&client_id={}",
            self.admin_base(),
            user_id,
            lifespan,
            encoded_redirect,
            encoded_client
        );
        let actions_json: Vec<serde_json::Value> = actions
            .iter()
            .map(|a| serde_json::Value::String(a.to_string()))
            .collect();
        let body = serde_json::Value::Array(actions_json);

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TideCloakError::Auth(format!(
                "Action link request failed ({status}): {text}"
            )));
        }
        Ok(resp.text().await.unwrap_or_default())
    }
}

/// URL-encode a string for use in URL path segments or query params.
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut encoded = String::with_capacity(s.len() * 3);
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                _ => {
                    encoded.push('%');
                    encoded.push_str(&format!("{:02X}", byte));
                }
            }
        }
        encoded
    }
}
