use rocket::serde::json::Json;
use rocket::Route;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    api::JsonResult,
    auth::AdminHeaders,
    db::{
        models::{
            AccessMetadata, AccessMetadataId, Collection,
            OrganizationId, PolicyApproval, PolicyApprovalId, PolicyLog, PolicyTemplate,
            PolicyTemplateId, RolePolicy,
        },
        DbConn,
    },
    error::Error,
};


pub fn routes() -> Vec<Route> {
    routes![
        // Templates
        list_templates,
        get_template,
        create_template,
        update_template,
        delete_template,
        // Policy Approvals
        create_policy_approval,
        list_pending_approvals,
        approve_policy,
        revoke_policy_decision,
        commit_policy,
        cancel_policy,
        // Access Metadata
        list_access_metadata,
        get_access_metadata,
        save_access_metadata,
        delete_access_metadata,
        // Roles
        list_roles,
        create_role,
        update_role,
        delete_role,
        // Role Policies
        get_role_policy,
        upsert_role_policy,
        delete_role_policy,
        // Policy Logs
        list_policy_logs,
        add_policy_log,
        // Users
        list_tide_users,
        create_tide_user,
        update_tide_user,
        delete_tide_user,
        add_tide_user_roles,
        remove_tide_user_roles,
        set_tide_user_enabled,
        get_tide_link_url,
        // Collection Access
        list_collections,
        get_user_collection_access,
        set_user_collection_access,
        remove_user_collection_access,
    ]
}

// ---------- Template Endpoints ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TemplateData {
    name: String,
    description: Option<String>,
    cs_code: Option<String>,
    parameters: Option<Value>,
}

#[get("/organizations/<org_id>/tide/templates")]
async fn list_templates(org_id: OrganizationId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    // Auto-seed the default Collection Owner template if none exist for this org
    let templates = PolicyTemplate::find_by_org(&org_id, &conn).await;
    if templates.is_empty() {
        seed_default_templates(&org_id, &headers.user.name, &conn).await;
        let templates = PolicyTemplate::find_by_org(&org_id, &conn).await;
        let json: Vec<Value> = templates.iter().map(PolicyTemplate::to_json).collect();
        return Ok(Json(json!(json)));
    }

    let json: Vec<Value> = templates.iter().map(PolicyTemplate::to_json).collect();
    Ok(Json(json!(json)))
}

/// Seeds default policy templates for an organization on first access.
async fn seed_default_templates(org_id: &OrganizationId, created_by: &str, conn: &DbConn) {
    let cs_code = r#"using Ork.Forseti.Sdk;
using System.Collections.Generic;

/// <summary>
/// Collection Owner Access Policy for TideWarden.
/// Grants access to users with the collectionOwner role.
/// </summary>
public class Contract : IAccessPolicy
{
    [PolicyParam(Required = true, Description = "Role required for collection owner access")]
    public string Role { get; set; }

    [PolicyParam(Required = true, Description = "Resource identifier for role check")]
    public string Resource { get; set; }

    public PolicyDecision ValidateData(DataContext ctx)
    {
        if (string.IsNullOrWhiteSpace(Role))
            return PolicyDecision.Deny("Role parameter is missing.");

        return PolicyDecision.Allow();
    }

    public PolicyDecision ValidateApprovers(ApproversContext ctx)
    {
        var approvers = DokenDto.WrapAll(ctx.Dokens);
        return Decision
            .Require(approvers != null && approvers.Count > 0, "No approver dokens provided")
            .RequireAnyWithRole(approvers, Resource, "tide-realm-admin");
    }

    public PolicyDecision ValidateExecutor(ExecutorContext ctx)
    {
        var executor = new DokenDto(ctx.Doken);
        return Decision
            .RequireNotExpired(executor)
            .RequireRole(executor, Resource, Role);
    }
}"#;

    let parameters = r#"[
        {"name":"Role","type":"string","helpText":"Role required for collection owner access","required":true,"defaultValue":"collectionOwner"},
        {"name":"Resource","type":"string","helpText":"Resource identifier for role check","required":true,"defaultValue":"tidewarden"}
    ]"#;

    let template = PolicyTemplate::new(
        org_id.clone(),
        "Collection Owner Access".to_string(),
        "Grants access to users with the collectionOwner role. Approvers must have the tide-realm-admin role.".to_string(),
        cs_code.to_string(),
        parameters.to_string(),
        created_by.to_string(),
    );
    drop(template.save(conn).await);
}

#[get("/organizations/<org_id>/tide/templates/<template_id>")]
async fn get_template(
    org_id: OrganizationId,
    template_id: PolicyTemplateId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match PolicyTemplate::find_by_uuid(&template_id, &conn).await {
        Some(t) => Ok(Json(t.to_json())),
        None => Err(Error::empty().with_code(404)),
    }
}

#[post("/organizations/<org_id>/tide/templates", data = "<data>")]
async fn create_template(
    org_id: OrganizationId,
    data: Json<TemplateData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();
    let params_str = serde_json::to_string(&data.parameters.unwrap_or(Value::Array(vec![]))).unwrap_or_default();
    let template = PolicyTemplate::new(
        org_id,
        data.name,
        data.description.unwrap_or_default(),
        data.cs_code.unwrap_or_default(),
        params_str,
        headers.user.name.clone(),
    );
    template.save(&conn).await?;
    Ok(Json(template.to_json()))
}

#[put("/organizations/<org_id>/tide/templates/<template_id>", data = "<data>")]
async fn update_template(
    org_id: OrganizationId,
    template_id: PolicyTemplateId,
    data: Json<TemplateData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let mut template = match PolicyTemplate::find_by_uuid(&template_id, &conn).await {
        Some(t) => t,
        None => err!("Template not found"),
    };
    let data = data.into_inner();
    template.name = data.name;
    if let Some(desc) = data.description {
        template.description = desc;
    }
    if let Some(code) = data.cs_code {
        template.cs_code = code;
    }
    if let Some(params) = data.parameters {
        template.parameters = serde_json::to_string(&params).unwrap_or_default();
    }
    template.updated_at = chrono::Utc::now().timestamp_millis();
    template.save(&conn).await?;
    Ok(Json(template.to_json()))
}

#[delete("/organizations/<org_id>/tide/templates/<template_id>")]
async fn delete_template(
    org_id: OrganizationId,
    template_id: PolicyTemplateId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match PolicyTemplate::find_by_uuid(&template_id, &conn).await {
        Some(t) => {
            t.delete(&conn).await?;
            Ok(Json(json!({})))
        }
        None => Err(Error::empty().with_code(404)),
    }
}

// ---------- Policy Approval Endpoints ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApproveData {
    rejected: Option<bool>,
    username: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeData {
    username: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatePolicyApprovalData {
    role_id: String,
    threshold: i32,
    policy_request_data: String,
    contract_code: Option<String>,
    requested_by_email: Option<String>,
}

#[post("/organizations/<org_id>/tide/policy-approvals", data = "<data>")]
async fn create_policy_approval(
    org_id: OrganizationId,
    data: Json<CreatePolicyApprovalData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();
    let approval = PolicyApproval::new(
        org_id,
        data.role_id,
        headers.user.name.clone(),
        data.requested_by_email.or(Some(headers.user.email.clone())),
        data.threshold,
        data.policy_request_data,
        data.contract_code,
    );
    approval.save(&conn).await?;
    Ok(Json(approval.to_json()))
}

#[get("/organizations/<org_id>/tide/policy-approvals")]
async fn list_pending_approvals(
    org_id: OrganizationId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let approvals = PolicyApproval::find_pending_by_org(&org_id, &conn).await;
    let json: Vec<Value> = approvals.iter().map(PolicyApproval::to_json).collect();
    Ok(Json(json!(json)))
}

#[post("/organizations/<org_id>/tide/policy-approvals/<approval_id>/approve", data = "<data>")]
async fn approve_policy(
    org_id: OrganizationId,
    approval_id: PolicyApprovalId,
    data: Json<ApproveData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let mut approval = match PolicyApproval::find_by_uuid(&approval_id, &conn).await {
        Some(a) => a,
        None => err!("Approval not found"),
    };
    let data = data.into_inner();
    let username = data.username.unwrap_or_else(|| headers.user.name.clone());
    let rejected = data.rejected.unwrap_or(false);

    if rejected {
        let mut denied: Vec<String> = serde_json::from_str(&approval.denied_by).unwrap_or_default();
        if !denied.contains(&username) {
            denied.push(username);
        }
        approval.denied_by = serde_json::to_string(&denied).unwrap_or_default();
        approval.rejection_count = denied.len() as i32;
    } else {
        let mut approved: Vec<String> = serde_json::from_str(&approval.approved_by).unwrap_or_default();
        if !approved.contains(&username) {
            approved.push(username);
        }
        approval.approved_by = serde_json::to_string(&approved).unwrap_or_default();
        approval.approval_count = approved.len() as i32;
        approval.commit_ready = approval.approval_count >= approval.threshold;
    }

    approval.save(&conn).await?;
    Ok(Json(json!({})))
}

#[post("/organizations/<org_id>/tide/policy-approvals/<approval_id>/revoke", data = "<data>")]
async fn revoke_policy_decision(
    org_id: OrganizationId,
    approval_id: PolicyApprovalId,
    data: Json<RevokeData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let mut approval = match PolicyApproval::find_by_uuid(&approval_id, &conn).await {
        Some(a) => a,
        None => err!("Approval not found"),
    };
    let username = data.into_inner().username.unwrap_or_else(|| headers.user.name.clone());

    let mut approved: Vec<String> = serde_json::from_str(&approval.approved_by).unwrap_or_default();
    approved.retain(|u| u != &username);
    approval.approved_by = serde_json::to_string(&approved).unwrap_or_default();
    approval.approval_count = approved.len() as i32;

    let mut denied: Vec<String> = serde_json::from_str(&approval.denied_by).unwrap_or_default();
    denied.retain(|u| u != &username);
    approval.denied_by = serde_json::to_string(&denied).unwrap_or_default();
    approval.rejection_count = denied.len() as i32;

    approval.commit_ready = approval.approval_count >= approval.threshold;
    approval.save(&conn).await?;
    Ok(Json(json!({})))
}

#[post("/organizations/<org_id>/tide/policy-approvals/<approval_id>/commit")]
async fn commit_policy(
    org_id: OrganizationId,
    approval_id: PolicyApprovalId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let mut approval = match PolicyApproval::find_by_uuid(&approval_id, &conn).await {
        Some(a) => a,
        None => err!("Approval not found"),
    };
    approval.status = "committed".to_string();
    approval.save(&conn).await?;
    Ok(Json(json!({})))
}

#[post("/organizations/<org_id>/tide/policy-approvals/<approval_id>/cancel")]
async fn cancel_policy(
    org_id: OrganizationId,
    approval_id: PolicyApprovalId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match PolicyApproval::find_by_uuid(&approval_id, &conn).await {
        Some(a) => {
            a.delete(&conn).await?;
            Ok(Json(json!({})))
        }
        None => Err(Error::empty().with_code(404)),
    }
}

// ---------- Access Metadata Endpoints ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessMetadataData {
    change_set_id: String,
    username: String,
    user_email: Option<String>,
    client_id: Option<String>,
    role: Option<String>,
    timestamp: Option<i64>,
    action_type: Option<String>,
    change_set_type: Option<String>,
}

#[get("/organizations/<org_id>/tide/access-metadata")]
async fn list_access_metadata(
    org_id: OrganizationId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let records = AccessMetadata::find_by_org(&org_id, &conn).await;
    let json: Vec<Value> = records.iter().map(AccessMetadata::to_json).collect();
    Ok(Json(json!(json)))
}

#[get("/organizations/<org_id>/tide/access-metadata/<change_set_id>")]
async fn get_access_metadata(
    org_id: OrganizationId,
    change_set_id: AccessMetadataId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match AccessMetadata::find_by_change_set_id(&change_set_id, &conn).await {
        Some(r) => Ok(Json(r.to_json())),
        None => Err(Error::empty().with_code(404)),
    }
}

#[post("/organizations/<org_id>/tide/access-metadata", data = "<data>")]
async fn save_access_metadata(
    org_id: OrganizationId,
    data: Json<AccessMetadataData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();
    let now = chrono::Utc::now().timestamp_millis();
    let record = AccessMetadata::new(
        data.change_set_id,
        org_id,
        data.username,
        data.user_email,
        data.client_id,
        data.role,
        data.timestamp.unwrap_or(now),
        data.action_type,
        data.change_set_type,
    );
    record.save(&conn).await?;
    Ok(Json(json!({})))
}

#[delete("/organizations/<org_id>/tide/access-metadata/<change_set_id>")]
async fn delete_access_metadata(
    org_id: OrganizationId,
    change_set_id: AccessMetadataId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match AccessMetadata::find_by_change_set_id(&change_set_id, &conn).await {
        Some(r) => {
            r.delete(&conn).await?;
            Ok(Json(json!({})))
        }
        None => Err(Error::empty().with_code(404)),
    }
}

// ---------- TideCloak Proxy Helpers ----------

/// Derive (auth_server_url, realm) from SSO_AUTHORITY config
fn tidecloak_config() -> Result<(String, String), Error> {
    let authority = crate::CONFIG.sso_authority();
    match authority.rfind("/realms/") {
        Some(idx) => Ok((authority[..idx].to_string(), authority[idx + 8..].to_string())),
        None => err!("Cannot derive auth server URL from SSO_AUTHORITY"),
    }
}

/// Get a fresh SSO access token for the admin user, refreshing if needed
async fn get_admin_sso_token(user_uuid: &crate::db::models::UserId, conn: &DbConn) -> Result<String, Error> {
    let sso_user = match crate::db::models::SsoUser::find_by_user_uuid(user_uuid, conn).await {
        Some(su) => su,
        None => err!("Admin user has no linked SSO account. Please log out and log back in."),
    };

    if let Some(ref sso_rt) = sso_user.sso_refresh_token {
        match crate::sso_client::Client::exchange_refresh_token(sso_rt.clone()).await {
            Ok((new_rt, access_token, _, _)) => {
                let rt = new_rt.as_deref().or(Some(sso_rt.as_str()));
                drop(crate::db::models::SsoUser::update_sso_tokens(user_uuid, &access_token, rt, conn).await);
                return Ok(access_token);
            }
            Err(e) => {
                error!("Failed to exchange SSO refresh token: {e:?}");
            }
        }
    }

    match sso_user.sso_access_token {
        Some(at) => Ok(at),
        None => err!("No SSO tokens stored. Please log out and log back in."),
    }
}

/// Make an authenticated request to TideCloak admin API
async fn tidecloak_request(
    method: reqwest::Method,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> Result<reqwest::Response, Error> {
    let client = reqwest::Client::new();
    let mut req = client.request(method, path)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"));
    if let Some(b) = body {
        req = req.json(&b);
    }
    req.send().await.map_err(|e| Error::new("TideCloak request failed", &e.to_string()))
}

/// Parse TideCloak error response
async fn check_tidecloak_response(resp: reqwest::Response) -> Result<reqwest::Response, Error> {
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        err!(format!("TideCloak API error: {status} {body}"));
    }
    Ok(resp)
}

// ---------- Role Endpoints (proxy to TideCloak) ----------

#[get("/organizations/<org_id>/tide/roles")]
async fn list_roles(org_id: OrganizationId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;
    let url = format!("{base_url}/admin/realms/{realm}/roles");
    let resp = tidecloak_request(reqwest::Method::GET, &url, &token, None).await?;
    let resp = check_tidecloak_response(resp).await?;
    let roles: Value = resp.json().await.map_err(|e| Error::new("Failed to parse roles", &e.to_string()))?;
    Ok(Json(roles))
}

#[post("/organizations/<org_id>/tide/roles", data = "<data>")]
async fn create_role(
    org_id: OrganizationId,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;
    let url = format!("{base_url}/admin/realms/{realm}/roles");
    let resp = tidecloak_request(reqwest::Method::POST, &url, &token, Some(data.into_inner())).await?;
    check_tidecloak_response(resp).await?;
    Ok(Json(json!({})))
}

#[put("/organizations/<org_id>/tide/roles/<role_name>", data = "<data>")]
async fn update_role(
    org_id: OrganizationId,
    role_name: String,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;
    let encoded = percent_encoding::utf8_percent_encode(&role_name, percent_encoding::NON_ALPHANUMERIC);
    let url = format!("{base_url}/admin/realms/{realm}/roles/{encoded}");
    let resp = tidecloak_request(reqwest::Method::PUT, &url, &token, Some(data.into_inner())).await?;
    check_tidecloak_response(resp).await?;
    Ok(Json(json!({})))
}

#[delete("/organizations/<org_id>/tide/roles/<role_name>")]
async fn delete_role(
    org_id: OrganizationId,
    role_name: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;
    let encoded = percent_encoding::utf8_percent_encode(&role_name, percent_encoding::NON_ALPHANUMERIC);
    let url = format!("{base_url}/admin/realms/{realm}/roles/{encoded}");
    let resp = tidecloak_request(reqwest::Method::DELETE, &url, &token, None).await?;
    check_tidecloak_response(resp).await?;
    Ok(Json(json!({})))
}

// ---------- Role Policy Endpoints ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RolePolicyData {
    role_name: String,
    enabled: bool,
    contract_type: Option<String>,
    approval_type: Option<String>,
    execution_type: Option<String>,
    threshold: Option<i32>,
    template_id: Option<String>,
    template_params: Option<Value>,
}

#[get("/organizations/<org_id>/tide/role-policies/<role_name>")]
async fn get_role_policy(
    org_id: OrganizationId,
    role_name: &str,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match RolePolicy::find_by_org_and_role_name(&org_id, role_name, &conn).await {
        Some(p) => Ok(Json(p.to_json())),
        None => Ok(Json(json!(null))),
    }
}

#[post("/organizations/<org_id>/tide/role-policies", data = "<data>")]
async fn upsert_role_policy(
    org_id: OrganizationId,
    data: Json<RolePolicyData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();
    let params_str = serde_json::to_string(&data.template_params.unwrap_or(json!({}))).unwrap_or_default();

    let policy = match RolePolicy::find_by_org_and_role_name(&org_id, &data.role_name, &conn).await {
        Some(mut existing) => {
            existing.enabled = data.enabled;
            if let Some(ct) = data.contract_type {
                existing.contract_type = ct;
            }
            if let Some(at) = data.approval_type {
                existing.approval_type = at;
            }
            if let Some(et) = data.execution_type {
                existing.execution_type = et;
            }
            if let Some(t) = data.threshold {
                existing.threshold = t;
            }
            existing.template_id = data.template_id;
            existing.template_params = params_str;
            existing.updated_at = chrono::Utc::now().timestamp_millis();
            existing.save(&conn).await?;
            existing
        }
        None => {
            let new_policy = RolePolicy::new(
                org_id,
                data.role_name,
                data.enabled,
                data.contract_type.unwrap_or_default(),
                data.approval_type.unwrap_or_else(|| "implicit".to_string()),
                data.execution_type.unwrap_or_else(|| "public".to_string()),
                data.threshold.unwrap_or(1),
                data.template_id,
                params_str,
            );
            new_policy.save(&conn).await?;
            new_policy
        }
    };
    Ok(Json(policy.to_json()))
}

#[delete("/organizations/<org_id>/tide/role-policies/<role_name>")]
async fn delete_role_policy(
    org_id: OrganizationId,
    role_name: &str,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    RolePolicy::delete_by_org_and_role_name(&org_id, role_name, &conn).await?;
    Ok(Json(json!({})))
}

// ---------- Policy Log Endpoints ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyLogData {
    policy_id: String,
    role_id: String,
    action: String,
    performed_by: String,
    performed_by_email: Option<String>,
    policy_status: Option<String>,
    policy_threshold: Option<i32>,
    approval_count: Option<i32>,
    rejection_count: Option<i32>,
    details: Option<String>,
}

#[derive(FromForm)]
struct LogPaginationParams {
    first: Option<i64>,
    max: Option<i64>,
}

#[get("/organizations/<org_id>/tide/policy-logs?<params..>")]
async fn list_policy_logs(
    org_id: OrganizationId,
    params: LogPaginationParams,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let offset = params.first.unwrap_or(0);
    let limit = params.max.unwrap_or(50);
    let logs = PolicyLog::find_by_org_paginated(&org_id, offset, limit, &conn).await;
    let json: Vec<Value> = logs.iter().map(PolicyLog::to_json).collect();
    Ok(Json(json!(json)))
}

#[post("/organizations/<org_id>/tide/policy-logs", data = "<data>")]
async fn add_policy_log(
    org_id: OrganizationId,
    data: Json<PolicyLogData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();
    let mut log = PolicyLog::new(
        org_id,
        data.policy_id,
        data.role_id,
        data.action,
        data.performed_by,
        data.performed_by_email,
    );
    log.policy_status = data.policy_status;
    log.policy_threshold = data.policy_threshold;
    log.approval_count = data.approval_count;
    log.rejection_count = data.rejection_count;
    log.details = data.details;
    log.save(&conn).await?;
    Ok(Json(json!({})))
}

// ---------- User Management Endpoints (proxy to TideCloak) ----------

#[get("/organizations/<org_id>/tide/users")]
async fn list_tide_users(org_id: OrganizationId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;
    let url = format!("{base_url}/admin/realms/{realm}/users");
    let resp = tidecloak_request(reqwest::Method::GET, &url, &token, None).await?;
    let resp = check_tidecloak_response(resp).await?;
    let users: Value = resp.json().await.map_err(|e| Error::new("Failed to parse users", &e.to_string()))?;
    Ok(Json(users))
}

#[post("/organizations/<org_id>/tide/users", data = "<data>")]
async fn create_tide_user(
    org_id: OrganizationId,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;
    let url = format!("{base_url}/admin/realms/{realm}/users");
    let resp = tidecloak_request(reqwest::Method::POST, &url, &token, Some(data.into_inner())).await?;
    check_tidecloak_response(resp).await?;
    Ok(Json(json!({})))
}

#[put("/organizations/<org_id>/tide/users/<user_id>", data = "<data>")]
async fn update_tide_user(
    org_id: OrganizationId,
    user_id: String,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;
    let url = format!("{base_url}/admin/realms/{realm}/users/{user_id}");
    let resp = tidecloak_request(reqwest::Method::PUT, &url, &token, Some(data.into_inner())).await?;
    check_tidecloak_response(resp).await?;
    Ok(Json(json!({})))
}

#[delete("/organizations/<org_id>/tide/users/<user_id>")]
async fn delete_tide_user(
    org_id: OrganizationId,
    user_id: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;
    let url = format!("{base_url}/admin/realms/{realm}/users/{user_id}");
    let resp = tidecloak_request(reqwest::Method::DELETE, &url, &token, None).await?;
    check_tidecloak_response(resp).await?;
    Ok(Json(json!({})))
}

#[post("/organizations/<org_id>/tide/users/<user_id>/roles", data = "<data>")]
async fn add_tide_user_roles(
    org_id: OrganizationId,
    user_id: String,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;

    // The UI sends { roles: ["roleName", ...] } but TideCloak expects [{ id, name }, ...]
    // Resolve role names to full role objects
    let input: Value = data.into_inner();
    let role_names: Vec<String> = match input.get("roles") {
        Some(Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => vec![],
    };

    let mut role_objects = Vec::new();
    for name in &role_names {
        let encoded = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
        let role_url = format!("{base_url}/admin/realms/{realm}/roles/{encoded}");
        let resp = tidecloak_request(reqwest::Method::GET, &role_url, &token, None).await?;
        if resp.status().is_success() {
            let role: Value = resp.json().await.unwrap_or_default();
            role_objects.push(role);
        }
    }

    let url = format!("{base_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm");
    let resp = tidecloak_request(reqwest::Method::POST, &url, &token, Some(json!(role_objects))).await?;
    check_tidecloak_response(resp).await?;
    Ok(Json(json!({})))
}

#[delete("/organizations/<org_id>/tide/users/<user_id>/roles", data = "<data>")]
async fn remove_tide_user_roles(
    org_id: OrganizationId,
    user_id: String,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;

    // Resolve role names to full role objects (TideCloak requires { id, name })
    let input: Value = data.into_inner();
    let role_names: Vec<String> = match input.get("roles") {
        Some(Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => vec![],
    };

    let mut role_objects = Vec::new();
    for name in &role_names {
        let encoded = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
        let role_url = format!("{base_url}/admin/realms/{realm}/roles/{encoded}");
        let resp = tidecloak_request(reqwest::Method::GET, &role_url, &token, None).await?;
        if resp.status().is_success() {
            let role: Value = resp.json().await.unwrap_or_default();
            role_objects.push(role);
        }
    }

    let url = format!("{base_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm");
    let resp = tidecloak_request(reqwest::Method::DELETE, &url, &token, Some(json!(role_objects))).await?;
    check_tidecloak_response(resp).await?;
    Ok(Json(json!({})))
}

#[put("/organizations/<org_id>/tide/users/<user_id>/enabled", data = "<data>")]
async fn set_tide_user_enabled(
    org_id: OrganizationId,
    user_id: String,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;
    let url = format!("{base_url}/admin/realms/{realm}/users/{user_id}");
    let resp = tidecloak_request(reqwest::Method::PUT, &url, &token, Some(data.into_inner())).await?;
    check_tidecloak_response(resp).await?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TideLinkData {
    redirect_uri: Option<String>,
    lifespan: Option<u64>,
}

#[post("/organizations/<org_id>/tide/users/<user_id>/tide-link", data = "<data>")]
async fn get_tide_link_url(
    org_id: OrganizationId,
    user_id: String,
    data: Json<TideLinkData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;

    let data = data.into_inner();
    let redirect_uri = data.redirect_uri.unwrap_or_else(|| crate::CONFIG.domain());
    let lifespan = data.lifespan.unwrap_or(43200);
    let client_id = crate::CONFIG.sso_client_id();

    // The user_id is now a TideCloak user UUID (passed directly from the UI)
    let params = format!(
        "userId={}&lifespan={}&redirect_uri={}&client_id={}",
        user_id,
        lifespan,
        percent_encoding::utf8_percent_encode(&redirect_uri, percent_encoding::NON_ALPHANUMERIC),
        percent_encoding::utf8_percent_encode(&client_id, percent_encoding::NON_ALPHANUMERIC),
    );
    let link_api_url = format!(
        "{base_url}/admin/realms/{realm}/tideAdminResources/get-required-action-link?{params}",
    );

    let resp = tidecloak_request(
        reqwest::Method::POST,
        &link_api_url,
        &token,
        Some(json!(["link-tide-account-action"])),
    ).await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        err!(format!("TideCloak link API error: {status} {body}"));
    }

    let link_url = resp
        .text()
        .await
        .map_err(|e| Error::new("Failed to read link URL response", &e.to_string()))?;

    Ok(Json(json!(link_url)))
}

// ---------- Collection Access Management ----------

/// List all collections in the org (for the collection access picker)
#[get("/organizations/<org_id>/tide/collections")]
async fn list_collections(org_id: OrganizationId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let collections = Collection::find_by_organization(&org_id, &conn).await;
    let json: Vec<Value> = collections
        .iter()
        .map(|c| json!({ "id": c.uuid, "name": c.name }))
        .collect();
    Ok(Json(json!(json)))
}

/// Get a user's collection access (parsed from their TideCloak realm role mappings)
#[get("/organizations/<org_id>/tide/users/<user_id>/collection-access")]
async fn get_user_collection_access(
    org_id: OrganizationId,
    user_id: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;

    // Get user's realm role mappings
    let url = format!("{base_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm");
    let resp = tidecloak_request(reqwest::Method::GET, &url, &token, None).await?;
    let resp = check_tidecloak_response(resp).await?;
    let roles: Vec<Value> = resp.json().await.unwrap_or_default();

    // Parse collection:*:* roles and enrich with collection names
    let collections = Collection::find_by_organization(&org_id, &conn).await;
    let mut access_list: Vec<Value> = Vec::new();

    for role in &roles {
        let name = match role.get("name").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let parts: Vec<&str> = name.splitn(3, ':').collect();
        if parts.len() != 3 || parts[0] != "collection" {
            continue;
        }
        let col_uuid = parts[1];
        let level = parts[2];
        // Only include recognized levels
        if !matches!(level, "read" | "read-hidden" | "write" | "manage") {
            continue;
        }
        let col_name = collections
            .iter()
            .find(|c| c.uuid.to_string() == col_uuid)
            .map(|c| c.name.as_str())
            .unwrap_or("Unknown Collection");

        access_list.push(json!({
            "collectionId": col_uuid,
            "collectionName": col_name,
            "accessLevel": level,
            "roleId": role.get("id").and_then(|v| v.as_str()).unwrap_or(""),
            "roleName": name,
        }));
    }

    Ok(Json(json!(access_list)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionAccessData {
    collection_id: String,
    access_level: String,
}

/// Set collection access for a user. Auto-creates the realm role if needed,
/// removes any conflicting access levels for the same collection.
#[post("/organizations/<org_id>/tide/users/<user_id>/collection-access", data = "<data>")]
async fn set_user_collection_access(
    org_id: OrganizationId,
    user_id: String,
    data: Json<CollectionAccessData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();

    // Validate access level
    if !matches!(data.access_level.as_str(), "read" | "read-hidden" | "write" | "manage") {
        err!("Invalid access level. Must be: read, read-hidden, write, or manage");
    }

    // Validate collection exists in this org
    let col_id: crate::db::models::CollectionId = data.collection_id.clone().into();
    if Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await.is_none() {
        err!("Collection not found in this organization");
    }

    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;
    let role_name = format!("collection:{}:{}", data.collection_id, data.access_level);

    // 1. Remove any existing collection:<uuid>:* roles for this collection from the user
    remove_collection_roles_for_user(&base_url, &realm, &token, &user_id, &data.collection_id).await?;

    // 2. Ensure the realm role exists (create if not)
    let role_obj = ensure_realm_role(&base_url, &realm, &token, &role_name).await?;

    // 3. Assign the role to the user
    let url = format!("{base_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm");
    let resp = tidecloak_request(reqwest::Method::POST, &url, &token, Some(json!([role_obj]))).await?;
    check_tidecloak_response(resp).await?;

    Ok(Json(json!({ "roleName": role_name })))
}

/// Remove all collection access for a specific collection from a user
#[delete("/organizations/<org_id>/tide/users/<user_id>/collection-access/<collection_id>")]
async fn remove_user_collection_access(
    org_id: OrganizationId,
    user_id: String,
    collection_id: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(&headers.user.uuid, &conn).await?;

    remove_collection_roles_for_user(&base_url, &realm, &token, &user_id, &collection_id).await?;
    Ok(Json(json!({})))
}

/// Helper: Remove all collection:<collection_id>:* realm roles from a user
async fn remove_collection_roles_for_user(
    base_url: &str,
    realm: &str,
    token: &str,
    user_id: &str,
    collection_id: &str,
) -> Result<(), Error> {
    let prefix = format!("collection:{collection_id}:");
    let url = format!("{base_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm");
    let resp = tidecloak_request(reqwest::Method::GET, &url, token, None).await?;
    if !resp.status().is_success() {
        return Ok(());
    }
    let roles: Vec<Value> = resp.json().await.unwrap_or_default();
    let to_remove: Vec<&Value> = roles
        .iter()
        .filter(|r| {
            r.get("name")
                .and_then(|n| n.as_str())
                .map(|n| n.starts_with(&prefix))
                .unwrap_or(false)
        })
        .collect();

    if !to_remove.is_empty() {
        let resp = tidecloak_request(
            reqwest::Method::DELETE,
            &url,
            token,
            Some(json!(to_remove)),
        )
        .await?;
        check_tidecloak_response(resp).await?;
    }
    Ok(())
}

/// Helper: Ensure a realm role exists, creating it if needed. Returns the full role object.
async fn ensure_realm_role(
    base_url: &str,
    realm: &str,
    token: &str,
    role_name: &str,
) -> Result<Value, Error> {
    let encoded = percent_encoding::utf8_percent_encode(role_name, percent_encoding::NON_ALPHANUMERIC);
    let role_url = format!("{base_url}/admin/realms/{realm}/roles/{encoded}");

    // Try to get the existing role
    let resp = tidecloak_request(reqwest::Method::GET, &role_url, token, None).await?;
    if resp.status().is_success() {
        return resp.json().await.map_err(|e| Error::new("Failed to parse role", &e.to_string()));
    }

    // Role doesn't exist — create it
    let roles_url = format!("{base_url}/admin/realms/{realm}/roles");
    let resp = tidecloak_request(
        reqwest::Method::POST,
        &roles_url,
        token,
        Some(json!({ "name": role_name })),
    )
    .await?;
    check_tidecloak_response(resp).await?;

    // Fetch the newly created role to get its full object (with id)
    let resp = tidecloak_request(reqwest::Method::GET, &role_url, token, None).await?;
    let resp = check_tidecloak_response(resp).await?;
    resp.json().await.map_err(|e| Error::new("Failed to parse created role", &e.to_string()))
}
