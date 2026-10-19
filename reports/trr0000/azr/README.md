# Elevated Access Toggle (Self-Elevation to Azure Root Scope)

## Metadata

| Key          | Value                             |
|--------------|-----------------------------------|
| ID           | TRR0000                           |
| External IDs | [AZT402], [T1098.003]             |
| Tactics      | Privilege Escalation, Persistence |
| Platforms    | IaaS, Identity Provider           |
| Contributors | John McGuinness                   |

### Scope Statement

A principal holding the Microsoft Entra ID Global Administrator
directory role invokes the Azure Resource Manager action
`Microsoft.Authorization/elevateAccess/action`, causing the platform to
create a User Access Administrator role assignment for that same
principal at Azure root scope `/`.

Direct self-assignment of an Azure RBAC role through
`Microsoft.Authorization/roleAssignments/write` is a separate technique: it
depends on an existing Azure RBAC write permission rather than on an Entra
directory role. Privileged Identity Management activation of an eligible
Global Administrator assignment is one way to satisfy this technique's
prerequisite, not an instance of it. Use of the root-scope assignment after
it exists is outside the boundary, because the success condition is the
assignment's existence.

## Technique Overview

A principal holding the Microsoft Entra ID Global Administrator directory
role invokes a single Azure Resource Manager action that grants that same
principal the Azure RBAC role User Access Administrator at root scope `/`,
the scope above every management group and subscription in the tenant. The
assignment it creates outlives the directory role that authorized it, which
gives the technique a persistence use as well as a privilege-escalation one.

## Technical Background

### Two Authorization Planes in a Microsoft Entra Tenant

Microsoft Entra ID and Azure resources are secured by two independent
authorization systems. Entra directory roles govern directory objects
such as users, groups, applications, domains, and licensing. Azure RBAC
governs Azure resources through Azure Resource Manager. Microsoft
states the separation directly: Microsoft Entra role assignments do not
grant access to Azure resources, Azure role assignments do not grant
access to Microsoft Entra ID, and by default the Global Administrator
does not have access to Azure resources. A tenant can hold a Global
Administrator who cannot read a single virtual machine, and a
subscription Owner whose Azure role grants nothing in the directory.

`Microsoft.Authorization/elevateAccess/action` is the documented mechanism
that carries a directory-plane identity into the resource plane: Microsoft
documents elevation as a Global Administrator capability, lists it under no
other directory role, and requires no Azure RBAC permission for it.

### Azure Scopes and Root Scope

Azure RBAC scopes nest: resource, resource group, subscription, management
group, and above all of them root scope `/`. The tenant root management
group sits below `/`; Microsoft's management groups overview and its
Defender for Cloud tenant-wide permissions article describe the resulting
grant as landing on the tenant root management group, but the assignment
the platform creates is scoped to `/`. Built-in role definitions carry an
`assignableScopes` value of `["/"]`, and custom role definitions cannot set
`assignableScopes` to `/` at all.

### The Elevate Access Action

The action is a single `POST` to
`/providers/Microsoft.Authorization/elevateAccess` on Azure Resource
Manager ([Global Administrator Elevate Access REST API - Microsoft Learn]).
The request carries no body and no parameter other than `api-version`, so
the caller cannot choose the principal, the role, or the scope: the platform
fixes all three as the caller, User Access Administrator (role definition
`18d7d88d-d35e-4fb5-a5c3-7773c20a72d9`), and `/`. User Access Administrator
combines read access to every Azure resource type with the full
`Microsoft.Authorization/*` and `Microsoft.Support/*` action sets, which
covers creating, modifying, and deleting role assignments and role
definitions ([Azure Built-in Roles Privileged - Microsoft Learn]).

The effect is per principal: Microsoft states that the
`Access management for Azure resources` setting is not a global property
and applies only to the currently signed-in user.

### Invocation Surfaces

The portal exposes the action as the `Access management for Azure
resources` toggle under the Microsoft Entra ID `Properties` blade. The same
action is reachable through raw Azure Resource Manager REST, the Azure CLI
generic REST command, and the Python, Go, JavaScript, and .NET management
SDKs; every surface resolves to the same action string against the same
endpoint. Azure PowerShell has no elevation cmdlet (Microsoft's guidance
points to the portal or the REST API and covers listing and removing the
assignment), and Microsoft Graph exposes no equivalent: Graph directory role
assignments are a different namespace from Azure RBAC scope `/`.

### Durability of the Resulting Assignment

The assignment the platform creates is an ordinary Azure RBAC role
assignment with its own lifecycle, and it is the durable product of the
technique. It is not time-bound: the `RoleAssignment` schema defines no
expiry property, and Microsoft's only lifecycle language on the toggle is a
recommendation to remove the access once the root-scope changes are made.

Deactivating a Privileged Identity Management eligible assignment of Global
Administrator does not remove the root-scope assignment; Microsoft states
that deactivation does not change the `Access management for Azure
resources` toggle to `No`. The assignment also survives removal of the
directory role that authorized it, a case Microsoft's documentation does
not address.

The assignment takes effect on the token already held, because Azure RBAC
assignments are evaluated per request rather than carried as token claims.
Microsoft's portal procedure directs the operator to sign out and back in,
a portal session behavior rather than a condition of the grant.

### Removal

There is no de-elevate action; Microsoft's `Microsoft.Authorization`
operation table contains nothing resembling an inverse. Removal is an
ordinary `Microsoft.Authorization/roleAssignments/delete` against the
assignment at scope `/`, and of the two platform logs below only the Entra
directory audit log gives the removal a dedicated activity name.

### Telemetry

Microsoft states that elevate access log entries appear in both the
Microsoft Entra directory audit logs and the Azure activity logs, and the
two records carry different strings for the same operation.

The Entra directory audit record lands in the `AuditLogs` table with a
`Category` of `AzureRBACRoleManagementElevateAccess`. The elevation carries
an `ActivityDisplayName` of `User has elevated their access to User Access
Administrator for their Azure Resources`; the removal carries `The role
assignment of User Access Administrator has been removed from the user`.

The Azure Activity Log record is a Directory Activity entry whose operation
display name is `Assigns the caller to User Access Administrator role`,
with an `authorization.action` of
`Microsoft.Authorization/elevateAccess/action`, an `authorization.scope` of
`/providers/Microsoft.Authorization`, a `category` of `Administrative`, and
an empty `subscriptionId`.

One invocation produces two Azure Activity Log records, a `Started` record
and a `Succeeded` record sharing an operation identifier, and one Entra
directory audit record stamped at the same moment as the `Succeeded`
record. Repeat invocation by an already elevated principal produces a
further full set of records while leaving the existing assignment in place.

The Azure Activity Log copy is a tenant-level Directory Activity record with
no diagnostic-setting export path: Microsoft documents activity log
diagnostic settings at subscription and management group scope and
retrieves tenant-level events through a separate REST API whose path
carries no subscription, and two vendor analyses reach the same conclusion
([Azure Apex Permissions Elevate Access - Permiso],
[Microsoft Entra Elevated Access Logs - Chance of Security]). Reading the
tenant-level activity log requires an Azure role assignment at scope `/`,
and Microsoft states that access to tenant-level activity logs requires
using elevate access at least once. The Entra directory audit copy is in
preview, which Microsoft's Azure RBAC changelog dates to January 2025.

Microsoft Defender for Resource Manager publishes an alert for the
operation, `ARM_AnomalousElevateAccess` (`Suspicious elevate access
operation`), drawn from Defender's internal sources and the Azure Activity
log, and the Defender for Resource Manager plan is enabled on a
subscription.

### Benign Use

Microsoft documents four legitimate reasons for elevating: regaining access
to a subscription or management group, granting a user access, seeing all
subscriptions in an organization, and allowing an automation application
tenant-wide access.

Two documented procedures run the full elevate-and-remove cycle. Microsoft
Defender for Cloud's tenant-wide visibility feature elevates the user,
creates the requested role assignment on the tenant root management group,
and removes the elevation, without the Global Administrator invoking
`Microsoft.Authorization/elevateAccess/action` by hand. Azure Lighthouse's
delegation-monitoring procedure has a Global Administrator elevate, assign
Monitoring Reader at root scope, and then remove the elevation.

### Real-World Usage

Microsoft's Storm-0501 reporting describes the actor taking over a synced
non-human identity that held Global Administrator and invoking
`Microsoft.Authorization/elevateAccess/action` by name. The
[MITRE ATT&CK Scattered Spider Group] entry records the assignment of user
access admin roles to gain `Tenant Root Group` management permissions in
Azure, without naming the action or root scope `/`.

## Procedures

| ID            | Title                              | Tactic                            |
|---------------|------------------------------------|-----------------------------------|
| TRR0000.AZR.A | Self-Elevation to Azure Root Scope | Privilege Escalation, Persistence |

### Procedure A: Self-Elevation to Azure Root Scope (TRR0000.AZR.A)

There is one procedure because the request exposes nothing to vary
([The Elevate Access Action]). Every surface in [Invocation Surfaces] emits
the same action against the same endpoint and produces the same records,
and the credential flow behind the token changes which sign-in table
records the prerequisite and how the records identify the caller, not which
operations the technique performs, so the portal, the CLI, raw REST, the
SDKs, and a workload identity holding the directory role are instances of
one path. No custom-role or Microsoft Graph path reaches the operation:
custom role definitions cannot set `assignableScopes` to `/`
([Azure Scopes and Root Scope]), so the action cannot be delegated at root
scope, and Graph exposes no equivalent surface.

Two prerequisites feed the single pipeline operation. `Hold Global
Administrator Role` is styled gray in the diagram as an external
prerequisite: acquiring the directory role leaves its own records, but the
acquisition belongs to the upstream technique that performed it, and within
this technique the role is state the caller holds rather than an operation
it performs, so the node carries no telemetry label.

The directory role reaches Azure Resource Manager as a claim: the role
template identifier `62e90394-69f5-4237-9190-012177145e10` is carried in
the `wids` claim of the access token, and the platform authorizes from the
presented token rather than from directory state, so a token issued while
the role was held satisfies the check for its remaining lifetime after the
role assignment is removed. The Azure RBAC assignment the technique creates
follows a different model ([Durability of the Resulting Assignment]).

`Obtain ARM Token` is the second prerequisite, because `elevateAccess` is
an Azure Resource Manager endpoint and the caller presents an access token
whose audience is Azure Resource Manager. The sign-in entry carries a
`ResourceDisplayName` of `Azure Resource Manager` and a `ResourceIdentity`
of `797f4846-ba00-4fd7-ba43-dac1f8f63013`, the Azure Resource Manager
application identifier.

The table the entry lands in is determined by the credential flow. An
interactive user sign-in produces
Entra SigninLogs (Azure Resource Manager) telemetry. A token obtained
silently from an existing session, which covers the refresh-token exchange
behind a command-line client and the portal's own silent acquisition,
produces Entra AADNonInteractiveUserSignInLogs (Azure Resource Manager)
telemetry. A service principal holding the directory role and presenting a
client credentials token for `https://management.azure.com/.default`
produces Entra AADServicePrincipalSignInLogs (Azure Resource Manager)
telemetry, and a managed identity holding the directory role and acquiring
the token from the instance metadata endpoint produces
Entra AADManagedIdentitySignInLogs (Azure Resource Manager) telemetry; both
receive the User Access Administrator assignment at `/` with a
`principalType` of `ServicePrincipal`. The sign-in entry records token
issuance rather than the invocation, so a token already held when the
action is invoked produces no sign-in entry at that moment.

The records identify the caller differently by principal type. In
Azure Activity Log Directory Activity
(Microsoft.Authorization/elevateAccess/action) telemetry the `caller` field
carries a user principal name for a user and a bare object identifier for a
service principal. In Entra AuditLogs (User has elevated their access to
User Access Administrator for their Azure Resources) telemetry the
`ActivityDisplayName` is the same string for every caller type, and the
caller is distinguished by which branch of `InitiatedBy` is populated:
`user` for a user, `app.servicePrincipalId` for a workload identity. An
application service principal and a managed identity are not
distinguishable from one another in either record; the two land in
different sign-in tables at the prerequisite.

The pipeline operation is `Elevate Access to Root Scope`. It produces
Entra AuditLogs (User has elevated their access to User Access
Administrator for their Azure Resources) telemetry carrying a
`LoggedByService` of `Azure RBAC (Elevated Access)`, and
Azure Activity Log Directory Activity
(Microsoft.Authorization/elevateAccess/action) telemetry; the other field
values of both records and the record count per invocation are given in
[Telemetry]. The role assignment the platform creates in the same
transaction is the outcome of this operation rather than a separate
operation, because no caller step sits between the request and the
assignment; its fixed attributes ([The Elevate Access Action]) are recorded
as properties of this operation.

#### Detection Data Model

![TRR0000.AZR.A DDM](ddms/trr0000_azr_a.png)

Red arrows run from both prerequisite nodes into
`Elevate Access to Root Scope`. `Obtain ARM Token` records the two scope
values in its `DelegatedScope` (`user_impersonation`) and
`ApplicationScope` (`.default`) properties, one per credential family, and
`Elevate Access to Root Scope` records a `PrincipalType` of
`User | ServicePrincipal`.

## Available Emulation Tests

| ID                                                       | Link                                              |
|----------------------------------------------------------|---------------------------------------------------|
| azure.privilege-escalation.root-user-access-administrator | [Stratus Red Team Root User Access Administrator] |

Atomic Red Team carries no test for this technique; its T1098.003 atomics
cover Entra directory role and Microsoft 365 role additions rather than the
Azure RBAC elevation.

## References

- [Azure Threat Research Matrix AZT402]
- [MITRE ATT&CK T1098.003]
- [MITRE ATT&CK Scattered Spider Group]
- [Elevate Access to Manage Azure Subscriptions - Microsoft Learn]
- [Global Administrator Elevate Access REST API - Microsoft Learn]
- [Azure.ResourceManager.Authorization Extensions - Microsoft Learn]
- [Azure Permissions for Management and Governance - Microsoft Learn]
- [Azure Roles and Microsoft Entra Roles - Microsoft Learn]
- [Azure RBAC Scope Overview - Microsoft Learn]
- [Azure Built-in Roles Privileged - Microsoft Learn]
- [Management Groups Overview - Microsoft Learn]
- [Azure Custom Role Limits - Microsoft Learn]
- [Azure Role Definition AssignableScopes - Microsoft Learn]
- [Microsoft Entra Built-in Roles - Microsoft Learn]
- [Roles Across Microsoft Services - Microsoft Learn]
- [Microsoft Graph unifiedRoleAssignment Resource - Microsoft Learn]
- [Microsoft Entra Audit Activity Reference - Microsoft Learn]
- [AuditLogs Table Schema - Microsoft Learn]
- [SigninLogs Table Schema - Microsoft Learn]
- [AADNonInteractiveUserSignInLogs Table Schema - Microsoft Learn]
- [AADServicePrincipalSignInLogs Table Schema - Microsoft Learn]
- [AADManagedIdentitySignInLogs Table Schema - Microsoft Learn]
- [Access Token Claims Reference - Microsoft Learn]
- [Token Protection Deployment Guide for Web Apps - Microsoft Learn]
- [Azure Monitor Activity Log - Microsoft Learn]
- [Defender for Cloud Resource Manager Alerts - Microsoft Learn]
- [Defender for Resource Manager Alert Sources - Microsoft Learn]
- [Azure RBAC What's New Changelog - Microsoft Learn]
- [Defender for Cloud Tenant-Wide Permissions Management - Microsoft Learn]
- [Azure Lighthouse Monitor Delegation Changes - Microsoft Learn]
- [Storm-0501 Evolving Techniques - Microsoft Security Blog]
- [Azure Apex Permissions Elevate Access - Permiso]
- [Microsoft Entra Elevated Access Logs - Chance of Security]
- [Stratus Red Team Root User Access Administrator]
- [Atomic Red Team T1098.003 Atomics]

[Azure Scopes and Root Scope]: #azure-scopes-and-root-scope
[Durability of the Resulting Assignment]: #durability-of-the-resulting-assignment
[Telemetry]: #telemetry
[Invocation Surfaces]: #invocation-surfaces
[The Elevate Access Action]: #the-elevate-access-action
[AZT402]: https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT402/AZT402/
[T1098.003]: https://attack.mitre.org/techniques/T1098/003/
[Azure Threat Research Matrix AZT402]: https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT402/AZT402/
[MITRE ATT&CK T1098.003]: https://attack.mitre.org/techniques/T1098/003/
[MITRE ATT&CK Scattered Spider Group]: https://attack.mitre.org/groups/G1015/
[Elevate Access to Manage Azure Subscriptions - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin
[Global Administrator Elevate Access REST API - Microsoft Learn]: https://learn.microsoft.com/en-us/rest/api/authorization/global-administrator/elevate-access
[Azure.ResourceManager.Authorization Extensions - Microsoft Learn]: https://learn.microsoft.com/dotnet/api/azure.resourcemanager.authorization.authorizationextensions
[Azure Permissions for Management and Governance - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/permissions/management-and-governance#microsoftauthorization
[Azure Roles and Microsoft Entra Roles - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/rbac-and-directory-admin-roles
[Azure RBAC Scope Overview - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/scope-overview
[Azure Built-in Roles Privileged - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/built-in-roles/privileged#user-access-administrator
[Management Groups Overview - Microsoft Learn]: https://learn.microsoft.com/azure/governance/management-groups/overview
[Azure Custom Role Limits - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/custom-roles#custom-role-limits
[Azure Role Definition AssignableScopes - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/role-definitions#assignablescopes
[Microsoft Entra Built-in Roles - Microsoft Learn]: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference#global-administrator
[Roles Across Microsoft Services - Microsoft Learn]: https://learn.microsoft.com/entra/identity/role-based-access-control/m365-workload-docs
[Microsoft Graph unifiedRoleAssignment Resource - Microsoft Learn]: https://learn.microsoft.com/graph/api/resources/unifiedroleassignment
[Microsoft Entra Audit Activity Reference - Microsoft Learn]: https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities#azure-rbac-elevated-access
[AuditLogs Table Schema - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/reference/tables/auditlogs
[SigninLogs Table Schema - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs
[AADNonInteractiveUserSignInLogs Table Schema - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs
[AADServicePrincipalSignInLogs Table Schema - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs
[AADManagedIdentitySignInLogs Table Schema - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs
[Access Token Claims Reference - Microsoft Learn]: https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
[Token Protection Deployment Guide for Web Apps - Microsoft Learn]: https://learn.microsoft.com/entra/identity/conditional-access/deployment-guide-token-protection-web-apps
[Azure Monitor Activity Log - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/platform/activity-log
[Defender for Cloud Resource Manager Alerts - Microsoft Learn]: https://learn.microsoft.com/azure/defender-for-cloud/alerts-resource-manager
[Defender for Resource Manager Alert Sources - Microsoft Learn]: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-resource-manager-usage
[Azure RBAC What's New Changelog - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/whats-new
[Defender for Cloud Tenant-Wide Permissions Management - Microsoft Learn]: https://learn.microsoft.com/azure/defender-for-cloud/tenant-wide-permissions-management
[Azure Lighthouse Monitor Delegation Changes - Microsoft Learn]: https://learn.microsoft.com/azure/lighthouse/how-to/monitor-delegation-changes
[Storm-0501 Evolving Techniques - Microsoft Security Blog]: https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
[Azure Apex Permissions Elevate Access - Permiso]: https://permiso.io/blog/azures-apex-permissions-elevate-access-the-logs-security-teams-overlook
[Microsoft Entra Elevated Access Logs - Chance of Security]: https://www.chanceofsecurity.com/post/microsoft-entra-elevated-access-logs-better-security-better-insights
[Stratus Red Team Root User Access Administrator]: https://stratus-red-team.cloud/attack-techniques/azure/azure.privilege-escalation.root-user-access-administrator/
[Atomic Red Team T1098.003 Atomics]: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.003/T1098.003.yaml
