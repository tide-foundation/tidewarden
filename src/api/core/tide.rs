use rocket::serde::json::Json;
use rocket::Route;
use serde::Deserialize;
use serde_json::Value;

use tidecloak_rs::AdminClient;

use crate::{
    api::JsonResult,
    auth::{AdminHeaders, Headers},
    db::{
        models::{
            AccessMetadata, AccessMetadataId, Collection, CollectionUser,
            Membership, MembershipStatus, MembershipType, OrganizationId, PolicyApproval,
            PolicyApprovalId, PolicyLog, PolicyTemplate, PolicyTemplateId, RolePolicy, User,
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
        // Committed Policies
        get_committed_policy,
        get_crypto_policy,
        reset_crypto_policy,
        // Admin Policy (proxy from TideCloak)
        get_admin_policy,
        // UserContext + VVK (proxy from TideCloak)
        get_tide_user_context,
        get_vvk_public,
        // Role Policy init-cert (proxy to TideCloak admin API)
        set_role_policy_init_cert,
        // Change Requests (proxy to TideCloak IGA change-set endpoints)
        list_change_requests_users,
        list_change_requests_roles,
        list_change_requests_clients,
        sign_change_request,
        commit_change_request,
        cancel_change_request,
        add_review_change_request,
        add_rejection_change_request,
        // Org Owner setup
        get_org_owner_status,
        create_org_owner_role,
        reset_org_owner_policy,
        // Update policy approval data (without approving)
        update_policy_approval_data,
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

    // Auto-seed the default Org Owner template if none exist for this org
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
    let cs_code = r#"using Cryptide.Key;
using Ork.Forseti.Sdk;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

public class Contract : IAccessPolicy
{
	[PolicyParam(Required = true, Description = "Allowed resource_access key (e.g. tidewarden)")]
	public string Resource { get; set; }

	private static bool TryExtractOrgId(string role, out string orgId)
	{
		orgId = "";
		if (!role.StartsWith("org:", StringComparison.Ordinal)) return false;
		var secondColon = role.IndexOf(':', 4);
		if (secondColon <= 4) return false;
		orgId = role.Substring(4, secondColon - 4);
		return orgId.Length > 0;
	}

	private static HashSet<string> CollectResourceRoles(JsonElement root, string resource)
	{
		var roles = new HashSet<string>(StringComparer.Ordinal);
		if (root.TryGetProperty("resource_access", out var ra) &&
			ra.TryGetProperty(resource, out var client) &&
			client.TryGetProperty("roles", out var arr) &&
			arr.ValueKind == JsonValueKind.Array)
		{
			foreach (var r in arr.EnumerateArray())
			{
				var s = r.GetString();
				if (s != null) roles.Add(s);
			}
		}
		return roles;
	}

	/// <summary>
	/// Read TideMemory field at index from byte[].
	/// Each field: 4-byte LE length prefix + data.
	/// </summary>
	private static bool TryReadField(byte[] buffer, int index, out byte[] result)
	{
		result = Array.Empty<byte>();
		int offset = 0;
		for (int i = 0; i <= index; i++)
		{
			if (offset + 4 > buffer.Length) return false;
			int len = BitConverter.ToInt32(buffer, offset);
			offset += 4;
			if (len < 0 || offset + len > buffer.Length) return false;
			if (i == index)
			{
				result = new byte[len];
				Array.Copy(buffer, offset, result, 0, len);
				return len > 0;
			}
			offset += len;
		}
		return false;
	}

	public PolicyDecision ValidateData(DataContext ctx)
	{
		if (ctx.Data == null || ctx.Data.Length == 0)
			return PolicyDecision.Deny("No data provided");
		if (ctx.DynamicData == null || ctx.DynamicData.Length == 0)
			return PolicyDecision.Deny("Dynamic data is empty");

		// [0] executor role -> extract org UUID
		if (!TryReadField(ctx.DynamicData, 0, out var roleBytes))
			return PolicyDecision.Deny("Role missing from dynamic data[0]");

		var executorRole = Encoding.UTF8.GetString(roleBytes);
		if (!TryExtractOrgId(executorRole, out var allowedOrgId))
			return PolicyDecision.Deny($"Cannot extract org UUID from role '{executorRole}'");

		var ownOrgPrefix = "org:" + allowedOrgId + ":";

		// [1] previous UC, [2] signature, [3] VVK public key
		HashSet<string> previousRoles;
		bool hasPreviousUc = TryReadField(ctx.DynamicData, 1, out var prevUcBytes);

		if (hasPreviousUc)
		{
			if (!TryReadField(ctx.DynamicData, 2, out var sigBytes))
				return PolicyDecision.Deny("Previous UC signature missing from dynamic data[2]");
			if (!TryReadField(ctx.DynamicData, 3, out var vvkPubBytes))
				return PolicyDecision.Deny("VVK public key missing from dynamic data[3]");

			try
			{
				var vvkKey = TideKey.From((ReadOnlyMemory<byte>)vvkPubBytes);
				if (!vvkKey.Verify((ReadOnlyMemory<byte>)prevUcBytes, (ReadOnlyMemory<byte>)sigBytes))
					return PolicyDecision.Deny("Previous UserContext signature verification failed");
			}
			catch (Exception ex)
			{
				return PolicyDecision.Deny($"Signature verification error: {ex.Message}");
			}

			JsonDocument prevDoc;
			try { prevDoc = JsonDocument.Parse(prevUcBytes); }
			catch (JsonException)
			{
				return PolicyDecision.Deny("Previous UserContext is not valid JSON");
			}
			using (prevDoc) { previousRoles = CollectResourceRoles(prevDoc.RootElement, Resource); }
		}
		else
		{
			previousRoles = new HashSet<string>(StringComparer.Ordinal);
		}

		// Validate each new UserContext in Draft
		int i = 0;
		bool found = false;

		while (TryReadField(ctx.Data, i, out var ucBytes))
		{
			found = true;
			if (ucBytes.Length == 0) { i++; continue; }

			JsonDocument doc;
			try { doc = JsonDocument.Parse(ucBytes); }
			catch (JsonException)
			{
				return PolicyDecision.Deny($"UserContext[{i}] is not valid JSON");
			}

			using (doc)
			{
				var root = doc.RootElement;

				if (root.TryGetProperty("realm_access", out _))
					return PolicyDecision.Deny($"UserContext[{i}] cannot contain realm_access");

				if (root.TryGetProperty("resource_access", out var resAccess))
				{
					if (resAccess.ValueKind != JsonValueKind.Object)
						return PolicyDecision.Deny($"UserContext[{i}] resource_access is not an object");

					foreach (var client in resAccess.EnumerateObject())
					{
						if (!client.Name.Equals(Resource, StringComparison.Ordinal))
							return PolicyDecision.Deny(
								$"UserContext[{i}] resource_access contains '{client.Name}' — only '{Resource}' allowed");

						if (!client.Value.TryGetProperty("roles", out var roles) ||
							roles.ValueKind != JsonValueKind.Array)
							return PolicyDecision.Deny(
								$"UserContext[{i}] resource_access.{Resource}.roles missing or not an array");

						foreach (var role in roles.EnumerateArray())
						{
							var r = role.GetString();
							if (r == null)
								return PolicyDecision.Deny($"UserContext[{i}] contains null role");

							if (r.StartsWith(ownOrgPrefix, StringComparison.Ordinal))
								continue;

							if (previousRoles.Contains(r))
								continue;

							return PolicyDecision.Deny(
								$"UserContext[{i}] role '{r}' is not scoped to org '{allowedOrgId}' and not pre-existing");
						}
					}
				}

				// Ensure non-org pre-existing roles are preserved
				var newRoles = CollectResourceRoles(root, Resource);
				foreach (var prev in previousRoles)
				{
					if (prev.StartsWith(ownOrgPrefix, StringComparison.Ordinal))
						continue;

					if (!newRoles.Contains(prev))
						return PolicyDecision.Deny(
							$"UserContext[{i}] cannot remove pre-existing role '{prev}'");
				}
			}

			i++;
		}

		if (!found) return PolicyDecision.Deny("No UserContexts found in data");
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
		if (ctx.DynamicData == null || ctx.DynamicData.Length == 0)
			return PolicyDecision.Deny("Dynamic data is empty");

		if (!TryReadField(ctx.DynamicData, 0, out var roleBytes))
			return PolicyDecision.Deny("Role missing from dynamic data[0]");

		var role = Encoding.UTF8.GetString(roleBytes);
		if (string.IsNullOrWhiteSpace(role))
			return PolicyDecision.Deny("Role in dynamic data is empty");

		if (!TryExtractOrgId(role, out _))
			return PolicyDecision.Deny($"Executor role '{role}' does not follow org:uuid:role pattern");

		var executor = new DokenDto(ctx.Doken);
		return Decision
			.RequireNotExpired(executor)
			.RequireRole(executor, Resource, role);
	}
}"#;

    let parameters = r#"[
        {"name":"Resource","type":"string","helpText":"Allowed resource_access key (e.g. tidewarden)","required":true,"defaultValue":"tidewarden"}
    ]"#;

    let template = PolicyTemplate::new(
        org_id.clone(),
        "Org Owner Access".to_string(),
        "Ensures the executor can only grant roles scoped to their own org. Trusts pre-existing roles from previous UserContext.".to_string(),
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
    policy_request_data: Option<String>,
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

        // Store the updated (enclave-signed) request data if provided
        if let Some(updated_request_data) = data.policy_request_data {
            approval.policy_request_data = updated_request_data;
        }
    }

    approval.save(&conn).await?;
    Ok(Json(json!({})))
}

/// Update policyRequestData and contractCode on a pending approval without changing approval status.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdatePolicyDataPayload {
    policy_request_data: Option<String>,
    contract_code: Option<String>,
}

#[put("/organizations/<org_id>/tide/policy-approvals/<approval_id>/data", data = "<data>")]
async fn update_policy_approval_data(
    org_id: OrganizationId,
    approval_id: PolicyApprovalId,
    data: Json<UpdatePolicyDataPayload>,
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
    if let Some(prd) = data.policy_request_data {
        approval.policy_request_data = prd;
    }
    if let Some(cc) = data.contract_code {
        approval.contract_code = Some(cc);
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitData {
    signed_policy_data: Option<String>,
    signed_policy_signature: Option<String>,
}

#[post("/organizations/<org_id>/tide/policy-approvals/<approval_id>/commit", data = "<data>")]
async fn commit_policy(
    org_id: OrganizationId,
    approval_id: PolicyApprovalId,
    data: Json<CommitData>,
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
    let signature_base64 = data.signed_policy_signature.clone();
    if let Some(signed_data) = data.signed_policy_data {
        approval.signed_policy_data = signed_data;
    }
    approval.status = "committed".to_string();
    approval.save(&conn).await?;

    // Store the policy on TideCloak's TideRoleDraftEntity via init-cert
    // Must send both initCert (full signed policy bytes) AND initCertSig (raw VVK signature)
    if !approval.signed_policy_data.is_empty() && !approval.role_id.is_empty() {
        let ac = build_admin_client(&headers.user.uuid, &conn).await?;
        let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;

        // role_id may be a name (e.g. "orgOwner") or a UUID — resolve to TideCloak UUID
        let role_id_for_api = if approval.role_id.contains('-') && approval.role_id.len() > 30 {
            approval.role_id.clone()
        } else {
            match ac.get_client_role(&client_uuid, &approval.role_id).await {
                Ok(role) => role.get("id").and_then(|v| v.as_str()).unwrap_or(&approval.role_id).to_string(),
                Err(_) => {
                    warn!("[Tide] Could not find TideCloak role for name '{}', using as-is", approval.role_id);
                    approval.role_id.clone()
                }
            }
        };

        let mut body = json!({ "initCert": approval.signed_policy_data });
        if let Some(ref sig) = signature_base64 {
            body["initCertSig"] = json!(sig);
            info!("[Tide] Including initCertSig ({} chars) for role {}", sig.len(), approval.role_id);
        } else {
            warn!("[Tide] No initCertSig provided for role {} — ORK policy verification may fail", approval.role_id);
        }
        match ac.tide_set_role_init_cert(&role_id_for_api, &body).await {
            Ok(_) => info!("[Tide] Stored policy initCert + initCertSig on TideCloak for role {}", approval.role_id),
            Err(e) => warn!("[Tide] Failed to store initCert on TideCloak: {e}"),
        }
    }

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

/// Get a fresh SSO access token for the admin user.
/// Always refreshes the token to ensure it's valid for TideCloak admin API calls.
async fn get_admin_sso_token(user_uuid: &crate::db::models::UserId, conn: &DbConn) -> Result<String, Error> {
    let sso_user = match crate::db::models::SsoUser::find_by_user_uuid(user_uuid, conn).await {
        Some(su) => su,
        None => err!("Admin user has no linked SSO account. Please log out and log back in."),
    };

    // Always try to refresh — tokens are short-lived (10 min) and likely expired
    if let Some(ref sso_rt) = sso_user.sso_refresh_token {
        match crate::sso_client::Client::exchange_refresh_token(sso_rt.clone()).await {
            Ok((new_rt, access_token, _, _)) => {
                let rt = new_rt.as_deref().or(Some(sso_rt.as_str()));
                drop(crate::db::models::SsoUser::update_sso_tokens(user_uuid, &access_token, rt, conn).await);
                info!("[Tide] Refreshed SSO token for admin user");
                return Ok(access_token);
            }
            Err(e) => {
                error!("[Tide] Failed to refresh SSO token: {e:?}");
                // Fall through to try stored token — it might still be valid
            }
        }
    }

    match sso_user.sso_access_token {
        Some(at) => {
            warn!("[Tide] Using stored SSO token (may be expired)");
            Ok(at)
        }
        None => err!("No SSO tokens stored. Please log out and log back in."),
    }
}

/// Build an AdminClient from SSO_AUTHORITY config and a fresh token for the given user.
async fn build_admin_client(
    user_uuid: &crate::db::models::UserId,
    conn: &DbConn,
) -> Result<AdminClient, Error> {
    let (base_url, realm) = tidecloak_config()?;
    let token = get_admin_sso_token(user_uuid, conn).await?;
    Ok(AdminClient::from_url(&base_url, &realm, &token))
}

/// Get the internal UUID of the TideCloak SSO client using AdminClient.
async fn get_tidecloak_client_uuid_ac(ac: &AdminClient) -> Result<String, Error> {
    let client_id = crate::CONFIG.sso_client_id();
    ac.find_client_uuid(&client_id).await
        .map_err(|e| { let d = e.to_string(); error!("[Tide] client lookup failed: {d}"); Error::new(format!("TideCloak client lookup failed: {d}"), &d) })
}

/// Ensure a client role exists, creating it if needed. Returns the full role object.
async fn ensure_client_role_ac(
    ac: &AdminClient,
    client_uuid: &str,
    role_name: &str,
) -> Result<Value, Error> {
    // Try to get the existing role
    match ac.get_client_role(client_uuid, role_name).await {
        Ok(role) => return Ok(role),
        Err(_) => {} // Role doesn't exist — create it
    }

    // Create the role
    ac.create_client_role(client_uuid, &json!({ "name": role_name }))
        .await
        .map_err(|e| Error::new("Failed to create client role", &e.to_string()))?;

    // Fetch the newly created role to get its full object (with id)
    ac.get_client_role(client_uuid, role_name)
        .await
        .map_err(|e| Error::new("Failed to fetch created role", &e.to_string()))
}

/// Add a realm-management role as a composite child of the given parent role.
async fn add_realm_management_composite_ac(
    ac: &AdminClient,
    parent_role_id: &str,
    role_name: &str,
) -> Result<(), Error> {
    let rm_client_uuid = ac.find_client_uuid("realm-management")
        .await
        .map_err(|e| Error::new("Failed to find realm-management client", &e.to_string()))?;

    let role = ac.get_client_role(&rm_client_uuid, role_name)
        .await
        .map_err(|e| Error::new(&format!("Failed to get {role_name} role"), &e.to_string()))?;

    ac.add_composite_roles(parent_role_id, &json!([role]))
        .await
        .map_err(|e| Error::new(&format!("Failed to add {role_name} composite"), &e.to_string()))?;
    Ok(())
}

/// Add all required realm-management roles as composites of the owner role.
async fn add_admin_composites_ac(ac: &AdminClient, owner_role_id: &str) -> Result<(), Error> {
    let roles = ["query-clients", "view-clients", "manage-clients", "query-users", "manage-users"];
    for role_name in &roles {
        match add_realm_management_composite_ac(ac, owner_role_id, role_name).await {
            Ok(()) => info!("[Tide] Added {role_name} composite to owner role"),
            Err(e) => warn!("[Tide] Failed to add {role_name} composite: {e}"),
        }
    }
    Ok(())
}

// ---------- Role Endpoints (proxy to TideCloak) ----------

#[get("/organizations/<org_id>/tide/roles")]
async fn list_roles(org_id: OrganizationId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;
    let roles = ac.get_client_roles(&client_uuid).await
        .map_err(|e| Error::new("Failed to list roles", &e.to_string()))?;
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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;
    ac.create_client_role(&client_uuid, &data.into_inner()).await
        .map_err(|e| Error::new("Failed to create role", &e.to_string()))?;
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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;
    // PUT to update requires the full URL; AdminClient doesn't have update_client_role yet,
    // so we use the existing role name as path
    let mut role_data = data.into_inner();
    if role_data.get("name").is_none() {
        role_data["name"] = json!(role_name);
    }
    // Delete + recreate is not ideal; AdminClient needs a PUT for client roles.
    // For now, use the raw put via base_url construction.
    let url = format!("{}/admin/realms/{}/clients/{}/roles/{}",
        ac.base_url(), ac.realm(), client_uuid, role_name);
    let http = reqwest::Client::new();
    let resp = http.put(&url)
        .bearer_auth(&get_admin_sso_token(&headers.user.uuid, &conn).await?)
        .json(&role_data)
        .send().await
        .map_err(|e| Error::new("Failed to update role", &e.to_string()))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        err!(format!("TideCloak API error: {status} {body}"));
    }
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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;
    ac.delete_client_role(&client_uuid, &role_name).await
        .map_err(|e| Error::new("Failed to delete role", &e.to_string()))?;
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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;

    let users = ac.get_users().await
        .map_err(|e| Error::new("Failed to list users", &e.to_string()))?;

    let org_prefix = format!("org:{org_id}:");

    // Filter to only users who have an org role for this organization
    let mut org_users: Vec<Value> = Vec::new();
    if let Some(arr) = users.as_array() {
        for tc_user in arr {
            if let Some(tc_id) = tc_user.get("id").and_then(|v| v.as_str()) {
                let has_org_role = match ac.get_user_client_roles(tc_id, &client_uuid).await {
                    Ok(roles) => roles.as_array().map_or(false, |arr| {
                        arr.iter().any(|role| {
                            role.get("name").and_then(|n| n.as_str()).map_or(false, |name| name.starts_with(&org_prefix))
                        })
                    }),
                    Err(_) => false,
                };

                if has_org_role {
                    org_users.push(tc_user.clone());
                }
            }
        }
    }

    Ok(Json(json!(org_users)))
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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;

    let user_data = data.into_inner();
    ac.create_user(&user_data).await
        .map_err(|e| Error::new("Failed to create user", &e.to_string()))?;

    // Look up the newly created TC user by email and assign org role directly
    if let Some(email) = user_data.get("email").and_then(|e| e.as_str()) {
        if let Ok(users) = ac.search_users_by_email(email).await {
            if let Some(tc_user) = users.first() {
                if let Some(tc_id) = tc_user.get("id").and_then(|v| v.as_str()) {
                    let role_name = format!("org:{org_id}:user");
                    match ensure_client_role_ac(&ac, &client_uuid, &role_name).await {
                        Ok(role_obj) => {
                            match ac.assign_user_client_roles(tc_id, &client_uuid, &json!([role_obj])).await {
                                Ok(_) => info!("[Tide] Assigned {role_name} to new user {tc_id}"),
                                Err(e) => warn!("[Tide] Failed to assign {role_name} to {tc_id}: {e}"),
                            }
                        }
                        Err(e) => warn!("[Tide] Failed to ensure role {role_name}: {e}"),
                    }

                    // Also create VW user + org membership
                    match resolve_vaultwarden_user_ac(&ac, tc_id, &conn).await {
                        Ok(vw_user) => {
                            if Membership::find_by_user_and_org(&vw_user.uuid, &org_id, &conn).await.is_none() {
                                let mut member = Membership::new(vw_user.uuid.clone(), org_id.clone(), None);
                                member.status = MembershipStatus::Accepted as i32;
                                member.atype = MembershipType::User as i32;
                                drop(member.save(&conn).await);
                                info!("[Tide] Auto-added new user {} to org {org_id} (needs confirm for org key)", vw_user.email);
                            }
                        }
                        Err(e) => warn!("[Tide] Could not auto-create VW user for new TC user: {e}"),
                    }
                }
            }
        }
    }

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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    ac.update_user(&user_id, &data.into_inner()).await
        .map_err(|e| Error::new("Failed to update user", &e.to_string()))?;
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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    ac.delete_user(&user_id).await
        .map_err(|e| Error::new("Failed to delete user", &e.to_string()))?;
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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;

    let input: Value = data.into_inner();
    let role_names: Vec<String> = match input.get("roles") {
        Some(Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => vec![],
    };

    let mut role_objects = Vec::new();
    for name in &role_names {
        if let Ok(role) = ac.get_client_role(&client_uuid, name).await {
            role_objects.push(role);
        }
    }

    ac.assign_user_client_roles(&user_id, &client_uuid, &json!(role_objects)).await
        .map_err(|e| Error::new("Failed to assign roles", &e.to_string()))?;
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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;

    let input: Value = data.into_inner();
    let role_names: Vec<String> = match input.get("roles") {
        Some(Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => vec![],
    };

    let mut role_objects = Vec::new();
    for name in &role_names {
        if let Ok(role) = ac.get_client_role(&client_uuid, name).await {
            role_objects.push(role);
        }
    }

    ac.remove_user_client_roles(&user_id, &client_uuid, &json!(role_objects)).await
        .map_err(|e| Error::new("Failed to remove roles", &e.to_string()))?;
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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    ac.update_user(&user_id, &data.into_inner()).await
        .map_err(|e| Error::new("Failed to update user", &e.to_string()))?;
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

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;

    let data = data.into_inner();
    let redirect_uri = data.redirect_uri.unwrap_or_else(|| crate::CONFIG.domain());
    let lifespan = data.lifespan.unwrap_or(43200);
    let client_id = crate::CONFIG.sso_client_id();

    let link_url = ac.tide_get_action_link(
        &user_id,
        &client_id,
        &redirect_uri,
        lifespan,
        &["link-tide-account-action"],
    ).await
        .map_err(|e| { let d = e.to_string(); error!("[Tide] link API error: {d}"); Error::new(format!("TideCloak link API error: {d}"), &d) })?;

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

/// Get a user's collection access (parsed from their TideCloak client role mappings)
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
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;

    let roles_val = ac.get_user_client_roles(&user_id, &client_uuid).await
        .map_err(|e| Error::new("Failed to get user client roles", &e.to_string()))?;
    let roles: Vec<Value> = serde_json::from_value(roles_val).unwrap_or_default();

    // Parse org:{orgId}:collection:{collId}:{level} roles and enrich with collection names
    let collections = Collection::find_by_organization(&org_id, &conn).await;
    let mut access_list: Vec<Value> = Vec::new();
    let org_prefix = format!("org:{org_id}:collection:");

    for role in &roles {
        let name = match role.get("name").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };
        // Expected format: org:{orgId}:collection:{collId}:{level}
        if !name.starts_with(&org_prefix) {
            continue;
        }
        let remainder = &name[org_prefix.len()..];
        let parts: Vec<&str> = remainder.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let col_uuid = parts[0];
        let level = parts[1];
        // Only include recognized levels
        if !matches!(level, "read" | "write" | "manage") {
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
    info!("[Tide] set_user_collection_access: org={org_id}, tc_user={user_id}, collection={}, level={}", data.collection_id, data.access_level);

    // Validate access level
    if !matches!(data.access_level.as_str(), "read" | "write" | "manage") {
        err!("Invalid access level. Must be: read, write, or manage");
    }

    // Validate collection exists in this org
    let col_id: crate::db::models::CollectionId = data.collection_id.clone().into();
    if Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await.is_none() {
        err!("Collection not found in this organization");
    }

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;
    let role_name = format!("org:{org_id}:collection:{}:{}", data.collection_id, data.access_level);

    // 1. Remove any existing org:{orgId}:collection:<uuid>:* roles for this collection from the user
    remove_collection_roles_for_user_ac(&ac, &client_uuid, &user_id, &org_id, &data.collection_id).await?;

    // 2. Ensure the client role exists (create if not)
    let role_obj = ensure_client_role_ac(&ac, &client_uuid, &role_name).await?;

    // 3. Assign the role to the user
    ac.assign_user_client_roles(&user_id, &client_uuid, &json!([role_obj])).await
        .map_err(|e| Error::new("Failed to assign role", &e.to_string()))?;
    info!("[Tide] TideCloak role assigned: {role_name}");

    // 4. Resolve TideCloak user → Vaultwarden user, ensure org membership, add to collection
    match resolve_vaultwarden_user_ac(&ac, &user_id, &conn).await {
        Ok(vw_user) => {
            info!("[Tide] Resolved TC user {user_id} → VW user {} ({})", vw_user.uuid, vw_user.email);
            // 4a. Ensure user is a member of the organization (needs admin confirm for org key)
            if Membership::find_by_user_and_org(&vw_user.uuid, &org_id, &conn).await.is_none() {
                let mut member = Membership::new(vw_user.uuid.clone(), org_id.clone(), None);
                member.status = MembershipStatus::Accepted as i32;
                member.atype = MembershipType::User as i32;
                member.save(&conn).await?;
                if let Err(e) = sync_membership_to_tidecloak(
                    &vw_user.uuid, &org_id, member.atype, member.access_all, &conn,
                ).await {
                    warn!("[Tide] Org role sync failed on set_user_collection_access: {e}");
                }
                info!("[Tide] Created org membership for user {}", vw_user.email);
            }
            // 4b. Add the user to the collection so they see items in the vault
            let (read_only, hide_passwords, manage) = access_level_to_permissions(&data.access_level);
            CollectionUser::save(&vw_user.uuid, &col_id, read_only, hide_passwords, manage, &conn).await?;
            info!("[Tide] Added user {} to collection {}", vw_user.email, data.collection_id);
        }
        Err(e) => {
            warn!("[Tide] Could not resolve TideCloak user {user_id} to Vaultwarden user: {e} — collection access not synced to vault");
        }
    }

    Ok(Json(json!({ "roleName": role_name })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveCollectionAccessData {
    collection_id: String,
}

/// Remove collection access for a specific collection from a user (with signed membership)
#[post("/organizations/<org_id>/tide/users/<user_id>/collection-access/remove", data = "<data>")]
async fn remove_user_collection_access(
    org_id: OrganizationId,
    user_id: String,
    data: Json<RemoveCollectionAccessData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;

    remove_collection_roles_for_user_ac(&ac, &client_uuid, &user_id, &org_id, &data.collection_id).await?;

    // Also remove the user from the Vaultwarden collection
    if let Ok(vw_user) = resolve_vaultwarden_user_ac(&ac, &user_id, &conn).await {
        let col_id: crate::db::models::CollectionId = data.collection_id.clone().into();
        if let Some(cu) = CollectionUser::find_by_collection_and_user(&col_id, &vw_user.uuid, &conn).await {
            cu.delete(&conn).await?;
        }
    } else {
        warn!("Could not resolve TideCloak user {user_id} to Vaultwarden user — collection removal not synced to vault");
    }

    Ok(Json(json!({})))
}

/// Helper: Remove all org:{org_id}:collection:{collection_id}:* client roles from a user
async fn remove_collection_roles_for_user_ac(
    ac: &AdminClient,
    client_uuid: &str,
    user_id: &str,
    org_id: &OrganizationId,
    collection_id: &str,
) -> Result<(), Error> {
    let prefix = format!("org:{org_id}:collection:{collection_id}:");
    let roles: Vec<Value> = match ac.get_user_client_roles(user_id, client_uuid).await {
        Ok(val) => serde_json::from_value(val).unwrap_or_default(),
        Err(_) => return Ok(()),
    };
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
        ac.remove_user_client_roles(user_id, client_uuid, &json!(to_remove)).await
            .map_err(|e| Error::new("Failed to remove collection roles", &e.to_string()))?;
    }
    Ok(())
}

/// Helper: Resolve a TideCloak user ID to a Vaultwarden User using AdminClient.
async fn resolve_vaultwarden_user_ac(
    ac: &AdminClient,
    tidecloak_user_id: &str,
    conn: &DbConn,
) -> Result<User, Error> {
    let issuer = format!("{}/realms/{}", ac.base_url(), ac.realm());
    let identifier = format!("{issuer}/{tidecloak_user_id}");
    if let Some((user, _sso)) = crate::db::models::SsoUser::find_by_identifier(&identifier, conn).await {
        return Ok(user);
    }

    let tc_user = ac.get_user(tidecloak_user_id).await
        .map_err(|e| Error::new("Failed to get TideCloak user", &e.to_string()))?;
    let email = tc_user.get("email").and_then(|e| e.as_str())
        .ok_or_else(|| Error::new("TideCloak user has no email", ""))?;

    if let Some(user) = User::find_by_mail(email, conn).await {
        let sso = crate::db::models::SsoUser {
            user_uuid: user.uuid.clone(),
            identifier: identifier.into(),
            tide_encrypted_key: None,
            sso_access_token: None,
            sso_refresh_token: None,
        };
        drop(sso.save(conn).await);
        info!("[Tide] Created SSO mapping for existing user {} → TC {tidecloak_user_id}", user.email);
        return Ok(user);
    }

    let name = match (tc_user.get("firstName").and_then(|v| v.as_str()), tc_user.get("lastName").and_then(|v| v.as_str())) {
        (Some(f), Some(l)) => format!("{f} {l}"),
        (Some(f), None) => f.to_string(),
        _ => tc_user.get("username").and_then(|v| v.as_str()).unwrap_or(email).to_string(),
    };
    let mut user = User::new(email, Some(name));
    user.verified_at = Some(chrono::Utc::now().naive_utc());
    user.save(conn).await?;
    info!("[Tide] Auto-created VW user {} for TC user {tidecloak_user_id}", user.email);

    let sso = crate::db::models::SsoUser {
        user_uuid: user.uuid.clone(),
        identifier: identifier.into(),
        tide_encrypted_key: None,
        sso_access_token: None,
        sso_refresh_token: None,
    };
    drop(sso.save(conn).await);

    Ok(user)
}

/// Map Tide access level strings to Vaultwarden CollectionUser permission flags.
fn access_level_to_permissions(level: &str) -> (bool, bool, bool) {
    match level {
        "read"    => (true,  false, false), // read_only, hide_passwords, manage
        "write"   => (false, false, false),
        "manage"  => (false, false, true),
        _         => (false, false, false),
    }
}

// ---------- Org Role → TideCloak Sync ----------

/// Map a Vaultwarden MembershipType integer to a TideCloak role suffix.
fn membership_type_to_suffix(atype: i32) -> &'static str {
    match atype {
        0 => "owner",
        1 => "admin",
        2 => "user",
        3 | 4 => "manager", // 4 = Custom, treated as Manager
        _ => "user",
    }
}

/// Resolve a Vaultwarden user UUID → TideCloak user ID using AdminClient.
async fn resolve_tidecloak_user_id_ac(
    ac: &AdminClient,
    user_uuid: &crate::db::models::UserId,
    conn: &DbConn,
) -> Result<String, Error> {
    let issuer = format!("{}/realms/{}", ac.base_url(), ac.realm());

    if let Some(sso_user) = crate::db::models::SsoUser::find_by_user_uuid(user_uuid, conn).await {
        let ident = sso_user.identifier.to_string();
        let prefix = format!("{issuer}/");
        if let Some(tc_id) = ident.strip_prefix(&prefix) {
            if !tc_id.is_empty() {
                return Ok(tc_id.to_string());
            }
        }
    }

    let vw_user = User::find_by_uuid(user_uuid, conn).await
        .ok_or_else(|| Error::new("VW user not found", &user_uuid.to_string()))?;
    let users = ac.search_users_by_email(&vw_user.email).await
        .map_err(|e| Error::new("Failed to search TideCloak users", &e.to_string()))?;
    match users.first().and_then(|u| u.get("id")).and_then(|v| v.as_str()) {
        Some(tc_id) => Ok(tc_id.to_string()),
        None => err!(format!("TideCloak user not found for email {}", vw_user.email)),
    }
}

/// Remove all org:{org_id}:* client roles from a TideCloak user.
async fn remove_org_roles_for_user_ac(
    ac: &AdminClient,
    client_uuid: &str,
    tc_user_id: &str,
    org_id: &OrganizationId,
) -> Result<(), Error> {
    let prefix = format!("org:{org_id}:");
    let roles: Vec<Value> = match ac.get_user_client_roles(tc_user_id, client_uuid).await {
        Ok(val) => serde_json::from_value(val).unwrap_or_default(),
        Err(_) => return Ok(()),
    };
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
        ac.remove_user_client_roles(tc_user_id, client_uuid, &json!(to_remove)).await
            .map_err(|e| Error::new("Failed to remove org roles", &e.to_string()))?;
    }
    Ok(())
}

/// Sync a Vaultwarden org membership to TideCloak client roles.
///
/// Creates/assigns:
///   - `org:{orgId}:{owner|admin|user|manager}` — the membership type role
///   - `org:{orgId}:accessAll` — if access_all is true
///   - `org:{orgId}:perm:{name}` — for each true custom permission flag
///
/// Best-effort: returns Err on failure but callers should warn, not block.
pub async fn sync_membership_to_tidecloak(
    user_uuid: &crate::db::models::UserId,
    org_id: &OrganizationId,
    membership_type: i32,
    access_all: bool,
    conn: &DbConn,
) -> Result<(), Error> {
    sync_membership_to_tidecloak_with_actor(user_uuid, org_id, membership_type, access_all, None, conn).await
}

/// Sync with an explicit acting user whose token will be used for TideCloak API calls.
/// Use this when the target user may not have an SSO token yet (e.g. newly invited members).
pub async fn sync_membership_to_tidecloak_with_actor(
    user_uuid: &crate::db::models::UserId,
    org_id: &OrganizationId,
    membership_type: i32,
    access_all: bool,
    acting_user: Option<&crate::db::models::UserId>,
    conn: &DbConn,
) -> Result<(), Error> {
    info!("[Tide] sync_membership_to_tidecloak: user={user_uuid}, org={org_id}, type={membership_type}, access_all={access_all}");

    let token_user = acting_user.unwrap_or(user_uuid);
    let ac = build_admin_client(token_user, conn).await.map_err(|e| {
        error!("[Tide] sync FAILED — build_admin_client: {e}");
        e
    })?;
    info!("[Tide] sync step 1/6 OK — AdminClient built");

    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await.map_err(|e| {
        error!("[Tide] sync step 3/6 FAILED — get client uuid: {e}");
        e
    })?;
    info!("[Tide] sync step 3/6 OK — client_uuid={client_uuid}");

    let tc_user_id = resolve_tidecloak_user_id_ac(&ac, user_uuid, conn).await.map_err(|e| {
        error!("[Tide] sync step 4/6 FAILED — resolve_tidecloak_user_id: {e}");
        e
    })?;
    info!("[Tide] sync step 4/6 OK — tc_user_id={tc_user_id}");

    remove_org_roles_for_user_ac(&ac, &client_uuid, &tc_user_id, org_id).await.map_err(|e| {
        error!("[Tide] sync step 5/6 FAILED — remove_org_roles: {e}");
        e
    })?;
    info!("[Tide] sync step 5/6 OK — removed existing org roles");

    let suffix = membership_type_to_suffix(membership_type);
    let mut role_names: Vec<String> = vec![format!("org:{org_id}:{suffix}")];

    // Owner inherits accessAll via composite — only add explicitly for non-owner types
    if access_all && membership_type != 0 {
        role_names.push(format!("org:{org_id}:accessAll"));
    }

    if (membership_type == 3 || membership_type == 4) && access_all {
        role_names.push(format!("org:{org_id}:perm:createNewCollections"));
        role_names.push(format!("org:{org_id}:perm:editAnyCollection"));
        role_names.push(format!("org:{org_id}:perm:deleteAnyCollection"));
    }

    info!("[Tide] sync step 6/7 — ensuring & assigning roles: {:?}", role_names);

    let mut role_objs: Vec<Value> = Vec::new();
    for name in &role_names {
        let role_obj = ensure_client_role_ac(&ac, &client_uuid, name).await.map_err(|e| {
            error!("[Tide] sync step 6/7 FAILED — ensure_client_role({}): {e}", name);
            e
        })?;
        role_objs.push(role_obj);
    }

    // For owners, add orgOwner + manage-users as composites of org:{uuid}:owner
    if membership_type == 0 {
        let owner_role_name = format!("org:{org_id}:owner");
        if let Some(owner_role_obj) = role_objs.iter().find(|r| r.get("name").and_then(|n| n.as_str()) == Some(&owner_role_name)) {
            if let Some(owner_role_id) = owner_role_obj.get("id").and_then(|v| v.as_str()) {
                let org_owner_existed = ac.get_client_role(&client_uuid, "orgOwner").await.is_ok();
                let org_owner_role = if org_owner_existed {
                    ac.get_client_role(&client_uuid, "orgOwner").await
                        .map_err(|e| Error::new("Failed to get orgOwner role", &e.to_string()))?
                } else {
                    ensure_client_role_ac(&ac, &client_uuid, "orgOwner").await?
                };

                match ac.add_composite_roles(owner_role_id, &json!([org_owner_role])).await {
                    Ok(_) => info!("[Tide] sync — added orgOwner composite to {owner_role_name}"),
                    Err(e) => error!("[Tide] sync — add orgOwner composite: {e}"),
                }

                // Add accessAll as composite of owner
                {
                    let access_all_name = format!("org:{org_id}:accessAll");
                    match ensure_client_role_ac(&ac, &client_uuid, &access_all_name).await {
                        Ok(access_all_role) => {
                            match ac.add_composite_roles(owner_role_id, &json!([access_all_role])).await {
                                Ok(_) => info!("[Tide] sync — added {access_all_name} composite to {owner_role_name}"),
                                Err(e) => error!("[Tide] sync — failed to add {access_all_name} composite: {e}"),
                            }
                        }
                        Err(e) => error!("[Tide] sync — failed to ensure {access_all_name} role: {e}"),
                    }
                }

                if !org_owner_existed {
                    let org_owner_id = org_owner_role.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    if !org_owner_id.is_empty() {
                        match add_admin_composites_ac(&ac, org_owner_id).await {
                            Ok(()) => info!("[Tide] sync — added admin composites to new orgOwner"),
                            Err(e) => warn!("[Tide] sync — failed to add admin composites to orgOwner: {e}"),
                        }
                    }
                }

                // Create pending PolicyApprovals
                {
                    let existing = PolicyApproval::find_pending_by_org(org_id, conn).await;

                    let has_org_owner = existing.iter().any(|a| a.role_id == "orgOwner")
                        || PolicyApproval::find_committed_by_role("orgOwner", conn).await.is_some();
                    if !has_org_owner {
                        let approval = PolicyApproval::new(
                            org_id.clone(), "orgOwner".to_string(), user_uuid.to_string(),
                            None, 1, String::new(), None,
                        );
                        match approval.save(conn).await {
                            Ok(()) => info!("[Tide] sync — created pending PolicyApproval for orgOwner"),
                            Err(e) => error!("[Tide] sync — failed to create orgOwner PolicyApproval: {e}"),
                        }
                    }

                    let has_app_user = existing.iter().any(|a| a.role_id == "appUser")
                        || PolicyApproval::find_committed_by_role("appUser", conn).await.is_some();
                    if !has_app_user {
                        let approval = PolicyApproval::new(
                            org_id.clone(), "appUser".to_string(), user_uuid.to_string(),
                            None, 1, String::new(), None,
                        );
                        match approval.save(conn).await {
                            Ok(()) => info!("[Tide] sync — created pending PolicyApproval for appUser"),
                            Err(e) => error!("[Tide] sync — failed to create appUser PolicyApproval: {e}"),
                        }
                    }
                }

                // Ensure appUser role exists
                {
                    let app_user_role = ensure_client_role_ac(&ac, &client_uuid, "appUser").await
                        .map_err(|e| { error!("[Tide] sync — ensure appUser role: {e}"); e })?;

                    let user_role_name = format!("org:{org_id}:user");
                    if let Some(user_role_obj) = role_objs.iter().find(|r| r.get("name").and_then(|n| n.as_str()) == Some(&user_role_name)) {
                        if let Some(user_role_id) = user_role_obj.get("id").and_then(|v| v.as_str()) {
                            match ac.add_composite_roles(user_role_id, &json!([app_user_role])).await {
                                Ok(_) => info!("[Tide] sync — added appUser composite to {user_role_name}"),
                                Err(e) => error!("[Tide] sync — failed to add appUser composite: {e}"),
                            }
                        }
                    }
                }
            }
        }
    }

    if !role_objs.is_empty() {
        ac.assign_user_client_roles(&tc_user_id, &client_uuid, &json!(role_objs)).await
            .map_err(|e| {
                error!("[Tide] sync step 6/7 FAILED — assign role mappings: {e}");
                Error::new("Failed to assign roles", &e.to_string())
            })?;
    }

    info!("[Tide] Synced org membership to TideCloak: user={tc_user_id}, org={org_id}, roles={:?}", role_names);
    Ok(())
}

// ---------- Committed Policy Endpoints ----------

/// Get a committed policy's signed request data by role name.
/// Used by the frontend to pass committed policy bytes to the Tide enclave for signing operations.
#[get("/organizations/<org_id>/tide/committed-policies/<role_name>")]
async fn get_committed_policy(
    org_id: OrganizationId,
    role_name: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    // Find a committed policy approval for this role
    let approvals = PolicyApproval::find_by_org(&org_id, &conn).await;
    let committed = approvals.into_iter().find(|a| a.role_id == role_name && a.status == "committed");

    match committed {
        Some(approval) => Ok(Json(json!({
            "roleId": approval.role_id,
            "policyRequestData": approval.policy_request_data,
            "signedPolicyData": approval.signed_policy_data,
        }))),
        None => Ok(Json(json!(null))),
    }
}

/// Get the committed crypto policy for PolicyEnabledEncryption/Decryption.
/// Tries appUser first, then falls back to any committed policy with signed data.
/// Returns the signedPolicyData bytes that the frontend passes to TideCloak encrypt/decrypt calls.
#[get("/organizations/<_org_id>/tide/crypto-policy")]
async fn get_crypto_policy(
    _org_id: OrganizationId,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let _ = &headers; // Auth only — any authenticated user can fetch the crypto policy

    // Try appUser first, then any committed policy with signed_policy_data
    let committed = PolicyApproval::find_committed_by_role("appUser", &conn).await;
    let committed = match &committed {
        Some(a) if !a.signed_policy_data.is_empty() => committed,
        _ => PolicyApproval::find_any_committed(&conn).await,
    };

    match committed {
        Some(approval) if !approval.signed_policy_data.is_empty() => Ok(Json(json!({
            "signedPolicyData": approval.signed_policy_data,
        }))),
        _ => Ok(Json(json!(null))),
    }
}

/// Delete all appUser crypto policy approvals for the org so they can be re-created.
#[delete("/organizations/<org_id>/tide/crypto-policy")]
async fn reset_crypto_policy(
    org_id: OrganizationId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let approvals = PolicyApproval::find_by_role_and_org("appUser", &org_id, &conn).await;
    let count = approvals.len();
    for approval in approvals {
        approval.delete(&conn).await?;
    }
    info!("[Tide] Reset crypto policy: deleted {} appUser approval(s) for org {}", count, org_id.as_ref());
    Ok(Json(json!({ "deleted": count })))
}

// ---------- Admin Policy (proxy from TideCloak) ----------

/// Fetch the admin policy from TideCloak's public endpoint.
#[get("/organizations/<org_id>/tide/admin-policy")]
async fn get_admin_policy(
    org_id: OrganizationId,
    headers: AdminHeaders,
    _conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let (base_url, realm) = tidecloak_config()?;
    let ac = AdminClient::from_url(&base_url, &realm, ""); // public endpoint, no token needed
    let admin_policy_base64 = ac.tide_get_admin_policy().await
        .map_err(|e| Error::new("Failed to fetch admin policy", &e.to_string()))?;

    Ok(Json(json!({ "adminPolicy": admin_policy_base64 })))
}

/// Fetch a user's previous UserContext + VVK signature from TideCloak.
#[get("/organizations/<org_id>/tide/user-context/<tc_user_id>/<client_id>")]
async fn get_tide_user_context(
    org_id: OrganizationId,
    tc_user_id: String,
    client_id: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let body = ac.tide_get_user_context(&tc_user_id, &client_id).await
        .map_err(|e| Error::new("Failed to get user context", &e.to_string()))?;
    Ok(Json(body))
}

/// Fetch the VVK public key from TideCloak's public endpoint.
#[get("/organizations/<org_id>/tide/vvk-public")]
async fn get_vvk_public(
    org_id: OrganizationId,
    headers: AdminHeaders,
    _conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let (base_url, realm) = tidecloak_config()?;
    let ac = AdminClient::from_url(&base_url, &realm, "");
    let body = ac.tide_get_vvk_public().await
        .map_err(|e| Error::new("Failed to fetch VVK public key", &e.to_string()))?;
    Ok(Json(body))
}

/// Proxy to TideCloak admin API: POST /role-policy/{roleId}/init-cert
#[post("/organizations/<org_id>/tide/role-policy/<role_id>/init-cert", data = "<data>")]
async fn set_role_policy_init_cert(
    org_id: OrganizationId,
    role_id: String,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let body = ac.tide_set_role_init_cert(&role_id, &data.into_inner()).await
        .map_err(|e| Error::new("Failed to set init-cert", &e.to_string()))?;
    Ok(Json(body))
}

// ---------- Change Request Proxy Endpoints ----------

/// List pending user change requests from TideCloak IGA.
#[get("/organizations/<org_id>/tide/change-requests/users")]
async fn list_change_requests_users(
    org_id: OrganizationId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let body = ac.tide_list_change_requests("users").await
        .map_err(|e| Error::new("Failed to list user change requests", &e.to_string()))?;
    Ok(Json(body))
}

/// List pending role change requests from TideCloak IGA.
#[get("/organizations/<org_id>/tide/change-requests/roles")]
async fn list_change_requests_roles(
    org_id: OrganizationId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let body = ac.tide_list_change_requests("roles").await
        .map_err(|e| Error::new("Failed to list role change requests", &e.to_string()))?;
    Ok(Json(body))
}

/// List pending client change requests from TideCloak IGA.
#[get("/organizations/<org_id>/tide/change-requests/clients")]
async fn list_change_requests_clients(
    org_id: OrganizationId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let body = ac.tide_list_change_requests("clients").await
        .map_err(|e| Error::new("Failed to list client change requests", &e.to_string()))?;
    Ok(Json(body))
}

/// Inject policyRoleId and dynamicData from the org's committed PolicyApproval into the request body.
/// TideCloak's MultiAdmin signer reads dynamicData from the JSON and injects it into the
/// BaseTideRequest bytes as raw [len][data] pairs (no version header).
async fn inject_policy_data(body: &mut Value, org_id: &OrganizationId, approval: &PolicyApproval, ac: &AdminClient) {
    if let Value::Object(map) = body {
        // Resolve role name to TideCloak UUID if needed
        let role_id = if approval.role_id.contains('-') && approval.role_id.len() > 30 {
            approval.role_id.clone()
        } else {
            if let Ok(client_uuid) = get_tidecloak_client_uuid_ac(ac).await {
                ac.get_client_role(&client_uuid, &approval.role_id).await
                    .ok()
                    .and_then(|r| r.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
                    .unwrap_or_else(|| approval.role_id.clone())
            } else { approval.role_id.clone() }
        };
        info!("[Tide] inject_policy_data: resolved role_id '{}' -> '{}'", approval.role_id, role_id);
        map.insert("policyRoleId".to_string(), Value::String(role_id));

        let owner_role = format!("org:{}:owner", org_id.as_ref());

        // Query TideCloak for the affected user's committed UC + sig using the changeSetId
        let mut prev_uc = String::new();
        let mut prev_uc_sig = String::new();
        if let Some(change_set_id) = map.get("changeSetId").and_then(|v| v.as_str()).map(|s| s.to_string()) {
            // Attempt 1: Use the change-set-specific user-context endpoint
            info!("[Tide] inject_policy_data: fetching UC for change-set {change_set_id}");
            if let Ok(uc_body) = ac.tide_get_user_context_by_change_set(&change_set_id).await {
                prev_uc = uc_body.get("accessProof").and_then(|v| v.as_str()).unwrap_or("").to_string();
                prev_uc_sig = uc_body.get("accessProofSig").and_then(|v| v.as_str()).unwrap_or("").to_string();
                info!("[Tide] inject_policy_data: UC: accessProof={} chars, sig={} chars", prev_uc.len(), prev_uc_sig.len());
            }

            // Attempt 2: fallback via pending change sets list
            if prev_uc.is_empty() {
                warn!("[Tide] inject_policy_data: accessProof EMPTY, trying fallback...");
                if let Ok(changes_val) = ac.tide_list_change_requests("users").await {
                    if let Some(changes) = changes_val.as_array() {
                        for change in changes {
                            let cs_id = change.get("changeSetId").and_then(|v| v.as_str()).unwrap_or("");
                            if cs_id == change_set_id {
                                if let Some(records) = change.get("userRecord").and_then(|v| v.as_array()) {
                                    if let Some(record) = records.first() {
                                        let username = record.get("username").and_then(|v| v.as_str()).unwrap_or("");
                                        let record_client_id = record.get("clientId").and_then(|v| v.as_str()).unwrap_or("");
                                        info!("[Tide] inject_policy_data: found user '{username}' (client '{record_client_id}')");

                                        if let Ok(users) = ac.search_users_by_username(username).await {
                                            if let Some(tc_user) = users.first() {
                                                let tc_user_id = tc_user.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                                if !tc_user_id.is_empty() && !record_client_id.is_empty() {
                                                    if let Ok(uc_body) = ac.tide_get_user_context(tc_user_id, record_client_id).await {
                                                        prev_uc = uc_body.get("accessProof").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                                        prev_uc_sig = uc_body.get("accessProofSig").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                                        info!("[Tide] inject_policy_data: direct UC: accessProof={} chars, sig={} chars",
                                                            prev_uc.len(), prev_uc_sig.len());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                        }
                        if prev_uc.is_empty() {
                            warn!("[Tide] inject_policy_data: could not find UC for change-set {change_set_id}");
                        }
                    }
                }
            }
        }

        map.insert("dynamicData".to_string(), json!([owner_role, prev_uc, prev_uc_sig]));
        info!("[Tide] inject_policy_data: dynamicData: role={}, uc={} chars, sig={} chars",
            owner_role.len(), prev_uc.len(), prev_uc_sig.len());
    }
}

// ---------------------------------------------------------------------------
// TideMemory binary helpers
// ---------------------------------------------------------------------------
// TideMemory format: [4-byte LE version(1)] then N fields each [4-byte LE length][data]

/// Parse a TideMemory blob into its constituent fields (skips the 4-byte version header).
fn tide_memory_parse(data: &[u8]) -> Vec<Vec<u8>> {
    let mut fields = Vec::new();
    if data.len() < 4 {
        return fields;
    }
    let mut offset = 4; // skip version header
    while offset + 4 <= data.len() {
        let len = i32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;
        if len < 0 {
            break;
        }
        let len = len as usize;
        if offset + len > data.len() {
            break;
        }
        fields.push(data[offset..offset + len].to_vec());
        offset += len;
    }
    fields
}

/// Build a TideMemory blob from fields. Writes version 1 header then each field with length prefix.
fn tide_memory_build(fields: &[&[u8]]) -> Vec<u8> {
    let total: usize = 4 + fields.iter().map(|f| 4 + f.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&1i32.to_le_bytes()); // version = 1
    for field in fields {
        buf.extend_from_slice(&(field.len() as i32).to_le_bytes());
        buf.extend_from_slice(field);
    }
    buf
}

/// Post-process sign response: inject dynamic data into the changeSetDraftRequests bytes
/// (field 5 of the BaseTideRequest TideMemory).
///
/// TideCloak's MultiAdmin already injects dynamic data from the JSON request, but it only
/// has what we sent it. This function ensures the bytes match, and logs what's actually in them.
/// The inner dynamic data uses TideMemory format (4-byte version header + [len][data] pairs).
async fn inject_dynamic_data_into_sign_response(
    response_body: &mut Value,
    org_id: &OrganizationId,
    change_set_id: &str,
    ac: &AdminClient,
) {
    // Fetch previous UserContext + VVK signature for the affected user
    let mut prev_uc = String::new();
    let mut prev_uc_sig = String::new();
    if !change_set_id.is_empty() {
        match ac.tide_get_user_context_by_change_set(change_set_id).await {
            Ok(uc_body) => {
                prev_uc = uc_body.get("accessProof").and_then(|v| v.as_str()).unwrap_or("").to_string();
                prev_uc_sig = uc_body.get("accessProofSig").and_then(|v| v.as_str()).unwrap_or("").to_string();
            }
            Err(e) => warn!("[Tide] inject_dynamic: failed to fetch UC by change-set: {e}"),
        }
    }

    let owner_role = format!("org:{}:owner", org_id.as_ref());

    // Build inner dynamic data as TideMemory (4-byte version header + [len][data] pairs).
    // The contract's TryReadField skips a 4-byte header (pos = 4), so we must include it.
    let dynamic_data = tide_memory_build(&[
        owner_role.as_bytes(),
        prev_uc.as_bytes(),
        prev_uc_sig.as_bytes(),
    ]);

    info!("[Tide] inject_dynamic: built dynamic data: {} bytes (role={}, uc={} chars, sig={} chars)",
        dynamic_data.len(), owner_role.len(), prev_uc.len(), prev_uc_sig.len());

    // Process each item in the response and inject dynamic data into changeSetDraftRequests
    let items: Vec<&mut Value> = match response_body {
        Value::Array(arr) => arr.iter_mut().collect(),
        Value::Object(_) => vec![response_body],
        _ => return,
    };

    for item in items {
        let draft_b64 = match item.get("changeSetDraftRequests").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };

        // Decode the base64 BaseTideRequest bytes
        let request_bytes = match data_encoding::BASE64.decode(draft_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                warn!("[Tide] inject_dynamic: failed to decode changeSetDraftRequests base64: {e}");
                continue;
            }
        };

        // Parse the outer TideMemory (BaseTideRequest has 10 fields: 0=name..9=policy)
        let mut fields = tide_memory_parse(&request_bytes);
        if fields.len() < 6 {
            info!("[Tide] inject_dynamic: request has {} fields (need at least 6), skipping", fields.len());
            continue;
        }

        // Log what's currently in field 5 (existing dynamic data from TideCloak)
        let existing_dd = &fields[5];
        info!("[Tide] inject_dynamic: existing field 5 is {} bytes", existing_dd.len());
        if !existing_dd.is_empty() {
            // Try to parse as raw [len][data] pairs to see what TideCloak put there
            let mut dd_offset = 0;
            let mut dd_idx = 0;
            while dd_offset + 4 <= existing_dd.len() {
                let dd_len = i32::from_le_bytes([
                    existing_dd[dd_offset], existing_dd[dd_offset+1],
                    existing_dd[dd_offset+2], existing_dd[dd_offset+3],
                ]) as usize;
                dd_offset += 4;
                if dd_offset + dd_len > existing_dd.len() { break; }
                let dd_val = &existing_dd[dd_offset..dd_offset + dd_len];
                let preview = String::from_utf8_lossy(&dd_val[..dd_val.len().min(100)]);
                info!("[Tide] inject_dynamic: existing dd[{dd_idx}] = {} bytes: {preview}", dd_len);
                dd_offset += dd_len;
                dd_idx += 1;
            }
        }

        // Replace field 5 (dyanmicData) with our dynamic data
        fields[5] = dynamic_data.clone();

        // Rebuild the full BaseTideRequest TideMemory (with version header for the outer structure)
        let field_refs: Vec<&[u8]> = fields.iter().map(|f| f.as_slice()).collect();
        let new_request_bytes = tide_memory_build(&field_refs);

        // Re-encode to base64 and update the response
        let new_b64 = data_encoding::BASE64.encode(&new_request_bytes);
        if let Some(obj) = item.as_object_mut() {
            obj.insert("changeSetDraftRequests".to_string(), Value::String(new_b64));
            info!("[Tide] inject_dynamic: replaced changeSetDraftRequests ({} -> {} bytes)",
                request_bytes.len(), new_request_bytes.len());
        }
    }
}

/// Sign (approve) a change request via TideCloak IGA.
/// Injects policyRoleId from the org's committed policy before forwarding.
/// After getting the response, injects dynamic data into the BaseTideRequest bytes
/// so the Forseti contract can validate executor role and previous UserContext.
#[post("/organizations/<org_id>/tide/change-requests/sign", data = "<data>")]
async fn sign_change_request(
    org_id: OrganizationId,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;

    let mut body = data.into_inner();
    let change_set_id = body.get("changeSetId").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let has_committed_policy = if let Some(approval) = PolicyApproval::find_committed_by_role("orgOwner", &conn).await {
        info!("[Tide] sign: found committed orgOwner PolicyApproval role_id={}, status={}", approval.role_id, approval.status);
        inject_policy_data(&mut body, &org_id, &approval, &ac).await;
        info!("[Tide] sign: injected policyRoleId={:?}", body.get("policyRoleId"));
        true
    } else {
        warn!("[Tide] sign: NO committed orgOwner PolicyApproval found — will use default tide-realm-admin policy");
        false
    };

    // Verify dynamicData is present before forwarding
    if let Some(dd) = body.get("dynamicData") {
        info!("[Tide] sign: dynamicData present in body: {}", dd);
    } else {
        warn!("[Tide] sign: dynamicData is MISSING from body!");
    }
    info!("[Tide] sign: forwarding body={}", body);
    let mut body = ac.tide_sign_change_request(&body).await
        .map_err(|e| {
            let msg = format!("TideCloak sign failed: {e}");
            error!("[Tide] {msg}");
            Error::new(&msg, "")
        })?;

    // Inject dynamic data into the BaseTideRequest bytes so the Forseti contract
    // can read the executor role, previous UserContext, and VVK public key.
    if has_committed_policy {
        inject_dynamic_data_into_sign_response(&mut body, &org_id, &change_set_id, &ac).await;
    }

    Ok(Json(body))
}

/// Commit a change request via TideCloak IGA.
/// Injects policyRoleId from the org's committed policy before forwarding.
#[post("/organizations/<org_id>/tide/change-requests/commit", data = "<data>")]
async fn commit_change_request(
    org_id: OrganizationId,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;

    let mut body = data.into_inner();
    // Strip signedRequest — frontend sends it but TideCloak's ChangeSetRequest model doesn't have this field
    if let Value::Object(ref mut map) = body {
        map.remove("signedRequest");
    }
    let approval = PolicyApproval::find_committed_by_role("orgOwner", &conn).await;
    if let Some(approval) = approval {
        info!("[Tide] commit: found committed orgOwner PolicyApproval role_id={}, status={}", approval.role_id, approval.status);
        inject_policy_data(&mut body, &org_id, &approval, &ac).await;
    } else {
        warn!("[Tide] commit: NO committed orgOwner PolicyApproval found");
    }

    info!("[Tide] commit: forwarding body={body}");
    let body = ac.tide_commit_change_request(&body).await
        .map_err(|e| {
            let detail = e.to_string();
            error!("[Tide] commit failed: {detail}");
            Error::new(format!("TideCloak commit failed: {detail}"), &detail)
        })?;
    Ok(Json(body))
}

/// Cancel a change request via TideCloak IGA.
/// Injects policyRoleId from the org's committed policy before forwarding.
#[post("/organizations/<org_id>/tide/change-requests/cancel", data = "<data>")]
async fn cancel_change_request(
    org_id: OrganizationId,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;

    let mut body = data.into_inner();
    let approval = PolicyApproval::find_committed_by_role("orgOwner", &conn).await;
    if let Some(approval) = approval {
        inject_policy_data(&mut body, &org_id, &approval, &ac).await;
    }

    let body = ac.tide_cancel_change_request(&body).await
        .map_err(|e| { let d = e.to_string(); error!("[Tide] cancel failed: {d}"); Error::new(format!("TideCloak cancel failed: {d}"), &d) })?;
    Ok(Json(body))
}

// ---------- Change Request Review / Rejection ----------

/// Submit an approval (add-review) for a change request via TideCloak IGA.
/// TideCloak expects form-encoded params: changeSetId, changeSetType, actionType, requests.
#[post("/organizations/<org_id>/tide/change-requests/add-review", data = "<data>")]
async fn add_review_change_request(
    org_id: OrganizationId,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;

    let body = data.into_inner();
    let change_set_id = body.get("changeSetId").and_then(|v| v.as_str()).unwrap_or("");
    let change_set_type = body.get("changeSetType").and_then(|v| v.as_str()).unwrap_or("");
    let action_type = body.get("actionType").and_then(|v| v.as_str()).unwrap_or("");

    // requests is an array of base64-encoded signed request strings
    let requests: Vec<String> = match body.get("requests") {
        Some(Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => vec![],
    };

    let mut form_params: Vec<(&str, String)> = vec![
        ("changeSetId", change_set_id.to_string()),
        ("changeSetType", change_set_type.to_string()),
        ("actionType", action_type.to_string()),
    ];
    for req in &requests {
        form_params.push(("requests", req.clone()));
    }

    let text = ac.tide_add_review(&form_params).await
        .map_err(|e| { let d = e.to_string(); error!("[Tide] add-review failed: {d}"); Error::new(format!("TideCloak add-review failed: {d}"), &d) })?;
    Ok(Json(json!({ "message": text })))
}

/// Submit a rejection for a change request via TideCloak IGA.
#[post("/organizations/<org_id>/tide/change-requests/add-rejection", data = "<data>")]
async fn add_rejection_change_request(
    org_id: OrganizationId,
    data: Json<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;

    let body = data.into_inner();
    let change_set_id = body.get("changeSetId").and_then(|v| v.as_str()).unwrap_or("");
    let change_set_type = body.get("changeSetType").and_then(|v| v.as_str()).unwrap_or("");
    let action_type = body.get("actionType").and_then(|v| v.as_str()).unwrap_or("");

    let form_params: Vec<(&str, String)> = vec![
        ("changeSetId", change_set_id.to_string()),
        ("changeSetType", change_set_type.to_string()),
        ("actionType", action_type.to_string()),
    ];

    let text = ac.tide_add_rejection(&form_params).await
        .map_err(|e| { let d = e.to_string(); error!("[Tide] add-rejection failed: {d}"); Error::new(format!("TideCloak add-rejection failed: {d}"), &d) })?;
    Ok(Json(json!({ "message": text })))
}

// ---------- Org Owner Setup Endpoints ----------

/// Check if the orgOwner client role exists in TideCloak and whether its policy is committed.
#[get("/organizations/<org_id>/tide/org-owner-status")]
async fn get_org_owner_status(
    org_id: OrganizationId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;

    // Check if orgOwner role exists in TideCloak
    let (role_exists, role_id) = match ac.get_client_role(&client_uuid, "orgOwner").await {
        Ok(role) => {
            let id = role.get("id").and_then(|v| v.as_str()).map(|s| s.to_string());
            (true, id)
        }
        Err(_) => (false, None),
    };

    // Determine policy status
    let policy_status = if let Some(ref rid) = role_id {
        // Check for committed approval matching this role UUID
        let committed = PolicyApproval::find_any_committed(&conn).await;
        if committed.as_ref().map(|a| a.role_id.as_str()) == Some(rid.as_str()) {
            "committed"
        } else {
            // Check for pending approval matching this role UUID
            let pending = PolicyApproval::find_pending_by_org(&org_id, &conn).await;
            if pending.iter().any(|a| a.role_id == *rid) {
                "pending"
            } else {
                "none"
            }
        }
    } else {
        "none"
    };

    Ok(Json(json!({
        "roleExists": role_exists,
        "roleId": role_id,
        "policyStatus": policy_status
    })))
}

/// Create the orgOwner client role in TideCloak under the TideWarden SSO client.
#[post("/organizations/<org_id>/tide/org-owner-role")]
async fn create_org_owner_role(
    org_id: OrganizationId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;

    let role = ensure_client_role_ac(&ac, &client_uuid, "orgOwner").await?;
    let role_id = role.get("id").and_then(|v| v.as_str()).unwrap_or("");

    // Add realm-management admin composites to orgOwner so org owners can manage their own members
    if !role_id.is_empty() {
        match add_admin_composites_ac(&ac, role_id).await {
            Ok(()) => info!("[Tide] Added admin composites to orgOwner role"),
            Err(e) => warn!("[Tide] Failed to add admin composites to orgOwner: {e}"),
        }
    }

    // Set orgOwner as a default client role so all new users get it on login
    let default_body = json!([{
        "id": role_id,
        "name": "orgOwner",
        "clientRole": true,
        "containerId": client_uuid,
    }]);
    match ac.add_default_role(&default_body).await {
        Ok(_) => info!("[Tide] Set orgOwner as default client role"),
        Err(e) => warn!("[Tide] Failed to set orgOwner as default role: {e}"),
    }

    Ok(Json(json!({ "roleId": role_id, "roleName": "orgOwner" })))
}

/// Reset the orgOwner policy: delete all policy approvals and clear initCert on TideCloak.
/// This allows re-running the full policy creation + signing flow from scratch.
#[post("/organizations/<org_id>/tide/org-owner-reset")]
async fn reset_org_owner_policy(
    org_id: OrganizationId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    // Delete all policy approvals globally (orgOwner is a shared role across orgs)
    info!("[Tide] Resetting org owner policy — deleting all policy approvals");
    PolicyApproval::delete_all(&conn).await?;

    // Also clear initCert on TideCloak for the orgOwner role
    let ac = build_admin_client(&headers.user.uuid, &conn).await?;
    let client_uuid = get_tidecloak_client_uuid_ac(&ac).await?;

    let role_id_str = match ac.get_client_role(&client_uuid, "orgOwner").await {
        Ok(role) => {
            if let Some(role_id) = role.get("id").and_then(|v| v.as_str()) {
                // Store empty initCert to clear the old one
                let body = json!({ "initCert": "" });
                match ac.tide_set_role_init_cert(role_id, &body).await {
                    Ok(_) => info!("[Tide] Cleared initCert for orgOwner role"),
                    Err(e) => warn!("[Tide] Failed to clear initCert: {e}"),
                }
                Some(role_id.to_string())
            } else {
                None
            }
        }
        Err(_) => None,
    };

    // Create a new pending PolicyApproval so the user can go through the flow again
    if let Some(role_id) = role_id_str {
        let approval = PolicyApproval::new(
            org_id,
            role_id,
            headers.user.name.clone(),
            Some(headers.user.email.clone()),
            1,
            String::new(), // policyRequestData will be auto-generated by the frontend
            None,
        );
        approval.save(&conn).await?;
        info!("[Tide] Created new pending PolicyApproval {}", approval.uuid.as_ref());
    }

    Ok(Json(json!({ "success": true })))
}
