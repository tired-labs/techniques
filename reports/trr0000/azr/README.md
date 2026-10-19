# Steal Application Access Token (Microsoft Entra ID)

## Metadata

| Key          | Value                                                  |
|--------------|--------------------------------------------------------|
| ID           | TRR0000                                                |
| External IDs | [AZT203], [AZT601], [T1528]                            |
| Tactics      | Credential Access                                      |
| Platforms    | Identity Provider, Containers, IaaS, Office Suite, SaaS|
| Contributors | John McGuinness                                        |

### Scope Statement

This TRR covers OAuth access-token acquisition on Microsoft Entra ID where an
adversary causes a legitimate Entra ID OAuth flow to issue tokens to
attacker-controlled infrastructure, or extracts a token issued to an
Entra-attached managed identity or federated workload identity on a compromised
Azure compute or AKS resource.

The pipeline ends at the adversary's first receipt of the access or refresh
token; later use of the token is [T1550.001]. This TRR treats theft of an
application secret or certificate from disk, a repository, or a key vault as
[T1552], reads of a client's on-disk token cache as [T1552.001], and issuance
with a stolen secret or certificate on a legitimately consented principal as
[T1078.004]; issuance to a service principal the victim tenant was induced to
consent to is Procedure B. First-party authorization-code phishing, where the
victim authenticates to a Microsoft first-party `client_id`, is TRR0034 (OAuth
Authorization Code Phishing). Azure Arc-enabled servers, Azure Logic Apps
workflows (ATRM AZT601.3), federated identity credentials trusting issuers
outside Azure compute such as GitHub Actions, and authentication transfer are
not modeled.

## Technique Overview

An adversary obtains a Microsoft Entra ID access token or refresh token issued
on behalf of a user, service principal, managed identity, or federated workload
identity, and holds it outside the client the token was issued to. Entra ID
issues bearer tokens, which any party in possession can use without
demonstrating possession of a cryptographic key. Because the authentication
requirements were met when the token was issued, a replayed token grants the
adversary access to organizational resources even where the user satisfied
multifactor authentication.

## Technical Background

### Microsoft Identity Platform Endpoints

Microsoft gives
`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` and
`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` as example v2.0
authorization and token endpoints ([Microsoft Identity Platform OAuth 2.0 and
OpenID Connect Protocols]). Interactive user flows obtain authorization at
`/authorize` and redeem at `/token`. The device code flow uses two different
endpoints: the client posts to
`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode` and then
polls `/token` ([Microsoft Identity Platform OAuth 2.0 Device Authorization
Grant]). Client credentials and federated-credential exchange also redeem at
`/oauth2/v2.0/token` ([Microsoft Identity Platform Client Credentials Flow]).
The documented managed identity token requests go to the IMDS address, a
`localhost` service, or the URL in `IDENTITY_ENDPOINT` (see [The Instance
Metadata Service]), and AKS workload identity projects a Kubernetes service
account token into the pod and exchanges it at the Microsoft Entra v2 token
endpoint rather than through the IMDS resource flow ([Use Microsoft Entra
Workload ID on AKS]).

### Device Authorization Grant Internals

In the device authorization grant the device requesting the authorization is
not the same as the device from which the user grants access ([RFC 8628
OAuth 2.0 Device Authorization Grant]), and Microsoft states that Entra ID
has no reliable way to verify that the person who enters the code is signing
in from the device that generated it ([Dynamics 365 Warehouse Management App
User-Based Authentication]). The flow begins with the client posting
`client_id` and `scope` to `/oauth2/v2.0/devicecode`; the response carries
`device_code`, `user_code` (a short string shown to the user to identify the
session on a secondary device), `verification_uri`, and the `expires_in` and
polling `interval` values ([Microsoft Identity Platform OAuth 2.0 Device
Authorization Grant]). Microsoft gives `https://microsoft.com/devicelogin` as an
example of the URL the user visits ([MSAL Authentication Flows]). While the user
authenticates at the verification URI, the client polls `/oauth2/v2.0/token`
with `grant_type=urn:ietf:params:oauth:grant-type:device_code` and the
`device_code`. Once the user signs in, the device obtains access tokens and, if
`offline_access` was in the original `scope`, a refresh token. Neither
documented request includes a `redirect_uri`, PKCE, or `state` parameter. The
device code flow is available only for public client applications. Since June
2021 the device code flow includes a prompt that validates the user is signing
into the app they expect ([Microsoft Identity Platform Breaking Changes
Reference]).

### Authorization Code Flow Internals

The authorization code flow is a two-leg exchange: an `/authorize` request that
returns a code, then a `/token` request that redeems it ([Microsoft Identity
Platform OAuth 2.0 Authorization Code Flow]). The authorize request carries
`client_id`, `scope`, and a `redirect_uri` that must exactly match one
registered for the application. Once the user authenticates and grants consent,
the platform returns the code to the `redirect_uri`. The client redeems the code
with a POST to `/token` carrying `grant_type=authorization_code`, the code, and
the same `redirect_uri`; confidential web apps authenticate with a
`client_secret` or a `client_assertion` JWT signed with a registered
certificate. The response carries an access token and, only if `offline_access`
was requested, a refresh token. The OAuth 2.0 specification requires that a code
be used to redeem an access token only once ([MSAL Authentication Flows]), and
RFC 6749 recommends a maximum code lifetime of 10 minutes ([RFC 6749 OAuth 2.0
Authorization Framework]).

### Client Credentials and Federated Credential Exchange

Service-principal token issuance is a POST to `/oauth2/v2.0/token` with
`grant_type=client_credentials` ([Microsoft Identity Platform Client
Credentials Flow]). Microsoft documents three cases: a shared secret; a
certificate, where `client_assertion` is a JWT the application creates and
signs with the certificate registered for it; and a federated credential, where
`client_assertion` is a JWT the application gets from another identity
provider, such as Kubernetes, whose specifics are registered on the application
as a federated identity credential. The assertion cases set
`client_assertion_type` to
`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`. The `/.default` scope
value tells the platform to issue a token for the direct application
permissions configured for the resource, and refresh tokens are never granted
with this flow. In the client credentials flow, permissions are granted
directly to the application itself by an administrator, and no user is
involved. AKS workload identity presents the kubelet-projected service-account
JWT as the `client_assertion` ([Use Microsoft Entra Workload ID on AKS]). The
federated identity credential's `issuer`, `subject`, and `audience` values must
case-sensitively match the corresponding claims in the token ([Microsoft
Identity Platform Workload Identity Federation]); when the checks pass, the
platform issues an access token to the external workload.

### The Instance Metadata Service

The Instance Metadata Service is a REST API at the non-routable address
`169.254.169.254`, accessible only from within a running virtual machine
instance ([Azure Instance Metadata Service]). The security boundary of a
managed identity is the resource where it is used: all code and scripts running
on a virtual machine can request and retrieve tokens for any managed identity
available on it ([Use Managed Identities on an Azure VM to Acquire Access
Tokens]). A request must contain the header `Metadata: true`, which Microsoft
describes as a mitigation against server-side request forgery. The token request
is an HTTP GET naming the target resource's App ID URI in the `resource` query
parameter, which also appears in the issued token's `aud` claim. The response
`token_type` is `Bearer`, and the token is based on the managed identity's
service principal; Microsoft describes these tokens as representing the
application that accesses the resource and not any specific user ([App Service
Managed Identity Overview]). The managed identities subsystem caches tokens:
on-the-wire calls to Microsoft Entra ID result only when a cache miss occurs
because no token is in the subsystem cache, or when the cached token is expired.

App Service, Azure Functions, and Container Apps provide an internally
accessible REST endpoint for token retrieval: `IDENTITY_ENDPOINT` holds the URL
of the local token service and `IDENTITY_HEADER` holds a value the platform
rotates, which the caller adds as the `X-IDENTITY-HEADER` header on an HTTP GET
to `IDENTITY_ENDPOINT` ([App Service Managed Identity Overview], [App Service
Environment Variables and App Settings Reference], [Azure Container Apps Managed
Identities]). Azure Automation's runbook samples send `X-IDENTITY-HEADER` to the
URL in `IDENTITY_ENDPOINT` ([Enable Managed Identity for Azure Automation]).
Service Fabric exposes an HTTPS `localhost` token service that takes a `Secret`
header ([Service Fabric Managed Identity in Application Code]). The Container
Instances sample token request goes to the IMDS address with the `Metadata`
header set to `true`, or for Windows container instances to `IDENTITY_ENDPOINT`
with `IDENTITY_HEADER` ([Azure Container Instances Managed Identity]). In an AKS
cluster the IMDS endpoint is by default accessible from all pods; when IMDS
restriction is enabled, pods that are not on the host network cannot acquire
managed identity tokens from it ([AKS IMDS Restriction]).

### Access Token Structure

An Entra ID access token is a signed JSON web token ([Microsoft Identity
Platform Access Tokens]) whose claims are defined in the [Microsoft Identity
Platform Access Token Claims Reference]. A standard OAuth2 token contains no
certificate binding information; an mTLS proof-of-possession token includes a
`cnf` claim that binds the token to a certificate, a feature in private preview
that supports app-only tokens only ([Microsoft Identity Web Token Binding]).

### Token Lifetimes

An access token receives a random default lifetime between 60 and 90 minutes, or
up to 28 hours when both the client and the resource support Continuous Access
Evaluation ([Microsoft Identity Platform Configurable Token Lifetimes],
[Microsoft Entra Continuous Access Evaluation]). The refresh token Max Inactive
Time is 90 days and its Max Age is until-revoked ([Microsoft Identity Platform
Configurable Token Lifetimes]); a refresh token sent to a redirect URI
registered as `spa` expires after 24 hours ([Microsoft Identity Platform
OAuth 2.0 Authorization Code Flow]). The user has 15 minutes from the device
authorization request to sign in, the default `expires_in` of a device code
([Microsoft Identity Platform OAuth 2.0 Device Authorization Grant]).

### Conditional Access and Device Code Flow

The Conditional Access authentication flows condition explicitly targets device
code flow ([Microsoft Entra Conditional Access Authentication Flows]). Protocol
tracking state is sustained through subsequent refreshes, so a session that
began with device code flow can remain subject to authentication flows policies
on later redemptions. Starting July 1, 2026, all new Microsoft Entra tenants
block device code flow as part of security defaults ([Microsoft Entra Security
Defaults]). When the device code flow is used, the require-managed-device grant
control and device state conditions are not supported, because the device
performing authentication cannot provide its device state to the device that is
providing a code ([Microsoft Entra Conditional Access Grant Controls]).

### OAuth Consent Framework

Microsoft defines two permission types: delegated permissions, which allow an
application to act on a user's behalf and appear in the `scp` claim, and
application permissions, also known as app roles, used in the app-only scenario
without a signed-in user and carried in the `roles` claim ([Microsoft Identity
Platform Permissions and Consent Overview], [Microsoft Entra Application and
Delegated Permission Access Tokens]). Users can consent for their own data to
delegated permissions and administrators for all users; app-only permissions
always require a tenant administrator's consent ([Microsoft Identity Platform
Convert App to Multitenant]). The result of consent for Microsoft Graph is an
`OAuth2PermissionGrant` for delegated permissions or an `appRoleAssignment` for
application permissions; an `OAuth2PermissionGrant` carries `consentType`
`Principal` (one user) or `AllPrincipals` (all users, grantable by an
administrator) ([Microsoft Graph oAuth2PermissionGrant Resource]). Application
permissions can be granted through a consent experience ([Microsoft Graph
Service Principal App Role Assignment]).

Tenant user-consent settings offer three options: disable user consent so users
cannot grant permissions to applications; allow users to consent to applications
from verified publishers or the organization, but only for permissions the
administrator selects; or allow users to consent to all applications for any
permission that does not require admin consent ([Microsoft Entra User and Admin
Consent Overview]). When risk-based step-up consent is enabled (it is enabled by
default and changes behavior only when user consent is enabled), users cannot
consent to most newly registered multitenant apps that are not publisher
verified ([Microsoft Identity Platform Publisher Verification Overview],
[Microsoft Entra Risk-Based Step-Up Consent]). The Microsoft managed consent
policy, which is the default for a new tenant, lets end users consent to any
user-consentable delegated permission except a Microsoft-maintained list of
Microsoft Graph and Exchange Online scopes, among them listed scopes in the
Files, Sites, Mail, Calendars, Chat, Contacts, and People families ([Microsoft
Entra Manage App Consent Policies]).

Granting tenant-wide admin consent requires signing in as a user authorized to
consent on behalf of the organization. The grant-admin-consent page lists
Privileged Role Administrator for any permission on any API; Cloud Application
Administrator, AI Administrator, or Application Administrator for any
permission except Microsoft Graph app roles; and a custom directory role that
includes the permission to grant permissions to applications ([Microsoft Entra
Grant Tenant-Wide Admin Consent], [Microsoft Entra Built-In Roles Reference]).
The admin consent endpoint
`https://login.microsoftonline.com/{tenant}/v2.0/adminconsent` (also documented
as `/{tenant}/adminconsent`) requires a tenant administrator to sign in to
complete the request, application permissions are requested through the
`/.default` scope value, and the documented success redirect carries
`admin_consent=True`, `tenant`, `scope`, and `state` ([Microsoft Identity
Platform Admin Consent Endpoint]).

### Telemetry Surfaces

Entra ID sign-in logs have four types: interactive user sign-ins,
non-interactive user sign-ins, service principal sign-ins, and managed identity
sign-ins ([Microsoft Entra Sign-In Logs Overview]). An interactive sign-in is
one in which the user provides an authentication factor to Entra ID; a
non-interactive sign-in is done on behalf of a user by a client app or OS
component without the user providing a factor, and Microsoft's examples include
a client app using a refresh token to get an access token and a client using an
authorization code to get an access token and refresh token ([Microsoft Entra
Interactive User Sign-Ins], [Microsoft Entra Non-Interactive User Sign-Ins]).
Service principal sign-ins do not involve a user; the app provides its own
credential, such as a certificate or app secret, and Microsoft names an
application using a client secret in the OAuth client credentials flow as an
example ([Microsoft Entra Service Principal Sign-Ins]). Managed identity
sign-ins are performed by resources whose secrets Azure manages ([Microsoft
Entra Managed Identity Sign-Ins]). In a Log Analytics workspace the four types
are the `SigninLogs`, `AADNonInteractiveUserSignInLogs`,
`AADServicePrincipalSignInLogs`, and `AADManagedIdentitySignInLogs` tables
([Azure Monitor SigninLogs Table], [Microsoft Entra Diagnostic Settings Log
Options], [Azure Monitor AADNonInteractiveUserSignInLogs Table], [Azure Monitor
AADServicePrincipalSignInLogs Table], [Azure Monitor
AADManagedIdentitySignInLogs Table]).

`AuthenticationProtocol` lists the protocol type or grant type used in the
authentication, with `deviceCode` among the values the `SigninLogs` page
documents. `OriginalTransferMethod` carries the transfer method used to initiate
a session throughout all subsequent requests; the Graph `originalTransferMethod`
value for a session begun with device code flow is `deviceCodeFlow` ([Microsoft
Graph signIn Resource]). `ResultType` is defined as `0` for success on the
`SigninLogs` page. For non-interactive sign-ins performed by confidential
clients, the logged `IPAddress` is the original IP used for the original token
issuance, not the source of the refresh request ([Microsoft Entra
Non-Interactive User Sign-Ins]).

`AuditLogs` is the Microsoft Entra audit log, which captures changes to
applications, groups, users, and licenses, with the activity in
`ActivityDisplayName` ([Azure Monitor AuditLogs Table], [Microsoft Entra
Diagnostic Settings Log Options]). The Core Directory activity reference lists,
under category `ApplicationManagement`, the activities `Add app role assignment
to service principal`, `Add delegated permission grant`, `Add service
principal`, and `Consent to application` ([Microsoft Entra Audit Activity
Reference]); Microsoft maps `Consent to application` to a user granting
consent, `Add delegated permission grant` to granting delegated access, and
`Add app role assignment to service principal` to granting app-only access
([Microsoft Entra Audit Logs for App Permissions]).

Host-side, an outbound connection from the resource is observable as a Linux
auditd `SYSCALL` record, which a syscall rule naming `connect` starts when a
program makes that call ([Linux auditctl Manual Page], [Red Hat Auditing the
System]), and as Sysmon event ID 3 (NetworkConnect), which logs TCP and UDP
connections linked to a process, is disabled by default, and is defined in the
shared event manifest for Windows and Linux ([Sysmon], [Sysmon Common Event
Manifest]). A file read in a pod is observable as an auditd record under a watch
rule (`-w path`) or a syscall rule with `-F path`; an audit event contains a
`PATH` record for every path passed to the system call, and since glibc 2.26 the
`open()` wrapper issues the `openat()` system call ([Linux open Manual Page]).
`AKSAudit` contains all Kubernetes API server audit logs, requires diagnostic
settings, and carries `Verb` (the Kubernetes verb, or the lower-cased HTTP
method for non-resource requests) and `ObjectRef` (resource, namespace, name,
and subresource) ([Azure Monitor AKSAudit Table], [Kubernetes Auditing],
[Kubernetes Audit API Reference]). In the Kubernetes authorization model an HTTP
`POST` maps to the `create` verb ([Kubernetes Authorization Overview]).

## Procedures

| ID | Title | Tactic |
|---|---|---|
| TRR0000.AZR.A | Device Code Phishing | Credential Access |
| TRR0000.AZR.B | Multi-Tenant Illicit Consent Grant | Credential Access |
| TRR0000.AZR.C | Managed Identity Token Retrieval | Credential Access |
| TRR0000.AZR.D | AKS Workload Identity Token Theft | Credential Access |

### Procedure A: Device Code Phishing (TRR0000.AZR.A)

This procedure covers the device authorization grant initiated on a device in
the adversary's possession, with the victim granting access from another
device. The request and response shapes are stated in [Device Authorization
Grant Internals].

The adversary generates a legitimate device code request at
`/oauth2/v2.0/devicecode` and tricks the target into entering the `user_code` at
a legitimate Microsoft sign-in page ([Microsoft Security Blog - Storm-2372
Device Code Phishing]). The victim's authentication at the verification page
authenticates the adversary's session ([Microsoft Security
Blog - CaptiveCrunch]). The adversary's client polls `/oauth2/v2.0/token` with
the device-code grant type and captures the access and refresh tokens that are
generated; Microsoft states that the requesting client receives the tokens
through a back channel ([MSAL Authentication Flows]). Microsoft, Proofpoint, and
Huntress have each documented campaigns using this procedure, and Sekoia has
documented a phishing-as-a-service kit built on it ([Microsoft Security
Blog - Storm-2372 Device Code Phishing], [Microsoft Security Blog - AI-Enabled
Device Code Phishing 2026], [Proofpoint - Phishing for Device Code Authorization
Account Takeover], [Huntress - Railway PaaS M365 Token Replay Campaign],
[Sekoia - EvilTokens Device Code Phishing Part 1]).

The victim's device-code authentication is an `Entra SigninLogs (Interactive
sign-in)` row with `AuthenticationProtocol` = `deviceCode`; that placement
follows from the `deviceCode` value and the interactive sign-in definition in
[Telemetry Surfaces] and from Microsoft's authentication-flows page tying device
code flow events in the sign-in logs to that property, and no single Microsoft
sentence states it. No Microsoft page states whether the device code request is
logged, or that the device-code redemption at `/oauth2/v2.0/token` writes its
own `AADNonInteractiveUserSignInLogs` row.

![TRR0000.AZR.A DDM](ddms/trr0000_azr_a.png)

### Procedure B: Multi-Tenant Illicit Consent Grant (TRR0000.AZR.B)

This procedure covers consent in the victim tenant to an application the
adversary registered elsewhere, with two branches that end in different token
issuances: a delegated branch that redeems an authorization code, and an
application branch that issues a client-credentials token to the consented
application's service principal. The consent settings, the roles that may grant
application permissions, and the admin consent endpoint are stated in [OAuth
Consent Framework]; the code and client-credentials request shapes in
[Authorization Code Flow Internals] and [Client Credentials and Federated
Credential Exchange].

The prerequisite is an application registered with the sign-in audience
`AzureADMultipleOrgs`, which admits work or school accounts from any
organization's tenant ([Microsoft Identity Platform App Manifest Reference]).
An application object is the global representation for use across all tenants
and its service principal is the local representation in a specific tenant,
with changes to the object reflected only in the home tenant ([Microsoft
Identity Platform Application and Service Principal Objects]). The registration
is drawn gray: the victim tenant receives its first object for the application
at consent, and that the victim tenant records nothing of the registration is a
derivation from those statements, not a Microsoft statement.

On the delegated branch the victim authenticates at `/oauth2/v2.0/authorize`.
When a user from a different tenant signs in to the application for the first
time, Entra ID asks the user to consent to the requested permissions; if the
user consents, a service principal for the application is created in the user's
tenant and a delegation recording the consent is created in the directory
([Microsoft Identity Platform Convert App to Multitenant]). The platform then
returns the authorization code to the registered `redirect_uri`, and the
adversary redeems it at `/oauth2/v2.0/token` with
`grant_type=authorization_code` and the application's `client_secret` or
`client_assertion`. Whether the victim may consent at all depends on the tenant
user-consent setting, risk-based step-up consent, and the Microsoft managed
consent policy stated in [OAuth Consent Framework]. Microsoft states that the
consent prompt appears when no previous record of user or admin consent for the
required permissions exists ([Microsoft Entra User and Admin Consent
Overview]); a run against a grant created earlier can pass through the sign-in
and the code redemption with that earlier consent as its prerequisite, and no
Microsoft page states whether the consent audit rows are written again on such
a run.

On the application branch a tenant administrator signs in at the admin consent
endpoint, and for Microsoft Graph permissions the consent results in an
`appRoleAssignment`. The documented success redirect (see [OAuth Consent
Framework]) lists no `code` parameter, and the client-credentials page proceeds
from that response directly to a `/token` request authenticated by the
application's own credential. The application then requests its token with the
client-credentials grant and its own credential (see [Client Credentials and
Federated Credential Exchange]).

The victim's interactive sign-in is an `Entra SigninLogs (Interactive sign-in)`
row whose `AppId` column identifies the application. On the delegated branch
the consent produces `Entra AuditLogs (Consent to application)`, `Entra
AuditLogs (Add service principal)`, and `Entra AuditLogs (Add delegated
permission grant)` rows; the `Add service principal` row follows from consent
creating the service principal in the victim tenant. On the application branch,
that the admin consent run writes `Entra AuditLogs (Add app role assignment to
service principal)`, the activity Microsoft maps to granting app-only access,
is a derivation from that mapping and from the statement that application
permissions can be granted through a consent experience (see [OAuth Consent
Framework]); no Microsoft page shows the row for an admin consent run. The code
redemption is an `Entra AADNonInteractiveUserSignInLogs (Authorization code
redemption)` row, Microsoft's own example of a non-interactive sign-in. The
client-credentials issuance is an `Entra AADServicePrincipalSignInLogs (Client
credentials flow sign-in)` row carrying `ClientCredentialType`,
`ServicePrincipalId`, and `AppId`; that the row lands in the victim tenant's
log follows from consent creating the service principal there and the token
request naming that tenant in its path.

![TRR0000.AZR.B DDM](ddms/trr0000_azr_b.png)

### Procedure C: Managed Identity Token Retrieval (TRR0000.AZR.C)

This procedure covers a token request from code the adversary runs on an Azure
compute resource with an attached managed identity, against the managed identity
token endpoint. The endpoint, header, and caching facts are stated in [The
Instance Metadata Service]. No authorization-endpoint step appears in the
references, and that this procedure involves no user or consent step is a
derivation from the documented token requests and from the client-credentials
statement that no user is involved (see [Client Credentials and Federated
Credential Exchange]).

The prerequisite is code execution on the resource: Azure VM, App Service,
Function App, Container Instance, AKS node, Container App, Service Fabric, or
Automation Account, with a system-assigned or user-assigned identity. The
prerequisite is drawn gray because code execution on the resource is the access
vector, outside the technique's observable boundary, and any record the vector
produces belongs to the vector's own technique. From the resource the adversary
issues the token request to the managed identity token endpoint, using the
endpoint and header each host documents, and the response is a JWT bearer access
token based on the managed identity's service principal. A pod without the
`azure.workload.identity/use` label is not mutated by the
azure-workload-identity mutating admission webhook, so a credential chain that
falls through to managed identity ([Azure SDK Credential Chains]) calls node
IMDS, which is reachable from all pods by default, and obtains a token for an
identity attached to the node; that path is a derivation from those statements
and runs through this procedure rather than Procedure D, and Microsoft lists the
kubelet identity's default permissions as None ([AKS Managed Identity
Overview]).

The request is observable as `Linux auditd (connect syscall)` and `Sysmon 3
(NetworkConnect)` records for the connection to the token endpoint address. The
issuance is an `Entra AADManagedIdentitySignInLogs (Token issuance)` row
carrying `ServicePrincipalId` (the service principal that initiated the
sign-in), `ResourceIdentity` and `ResourceDisplayName` (the resource the
service principal signed into), and `ManagedServiceIdentity`. That the row is
written only when the request reaches Entra ID on a cache miss or an expired
cached token is a derivation from the cache statement in [The Instance Metadata
Service] and the managed identity sign-in table definition, and the adversary's
own request to the managed identity token endpoint has no Entra record
described in the references.

![TRR0000.AZR.C DDM](ddms/trr0000_azr_c.png)

### Procedure D: AKS Workload Identity Token Theft (TRR0000.AZR.D)

This procedure covers acquisition of a Kubernetes service account JWT that a
federated identity credential trusts, followed by its exchange at the Entra
token endpoint for an access token issued to the federated application. The
exchange request and the federated identity credential matching rules are
stated in [Client Credentials and Federated Credential Exchange]; the two
branches differ in how the assertion is obtained.

On the projected-token branch the prerequisite is code execution in a pod of an
AKS cluster configured for Microsoft Entra Workload ID. The prerequisite is
drawn gray for the reason given in Procedure C: code execution in the pod is the
access vector. Only pods carrying the label `azure.workload.identity/use:
"true"` are mutated by the admission webhook to inject the Azure environment
variables and the projected service account token volume, and the service
account carries the `azure.workload.identity/client-id` annotation naming the
Entra application ([Use Microsoft Entra Workload ID on AKS]). The adversary
reads the projected token from the file named by `AZURE_FEDERATED_TOKEN_FILE`;
Microsoft gives `/var/run/secrets/azure/tokens/azure-identity-token` as an
example path and calls the mount path an implementation detail of the webhook
that can change. The token is a signed JWT ([Kubernetes Authentication]), and
Kubernetes refreshes the projected token in place before it expires ([Kubernetes
Service Account Administration]). The read is observable as `Linux auditd
(open/openat syscall)` under a rule keyed on the path. `/proc/<pid>/environ`
holds the initial environment set at `execve`, so, as a derivation from that
statement and the variable holding a path, it yields the token file path and not
the token; `/proc/<pid>/mem` gives access to a process's memory pages under a
ptrace access-mode check ([Linux proc_pid_mem Manual Page], [Linux
proc_pid_environ Manual Page]). A procfs read opens a procfs path rather than
the token path, so a path-keyed audit rule covers the file read and not the
memory read; that is a derivation from the two manual pages and the audit rule
form.

On the TokenRequest branch the adversary mints the assertion instead of reading
it. The prerequisite is `create` rights on `serviceaccounts/token`, the right
Kubernetes says lets users create TokenRequests to issue tokens for existing
service accounts ([Kubernetes RBAC Good Practices]). The prerequisite is drawn
gray because holding the right is a standing authorization the API server
evaluates when the TokenRequest is made. The TokenRequest subresource of a
ServiceAccount, a `POST` to
`/api/v1/namespaces/{namespace}/serviceaccounts/{name}/token`, issues a
time-bound token for that service account with the audiences the caller requests
([Kubernetes Service Account Administration], [Kubernetes TokenRequest API
Reference]). Direct Entra workload identity federation requires a token with the
audience `api://AzureADTokenExchange`; when identity bindings are enabled the
identity binding webhook sets the default projected token's audience to
`api://AKSIdentityBinding` instead ([Use Microsoft Entra Workload ID on AKS]).
The federated identity credential for a service account names the subject
`system:serviceaccount:<namespace>:<name>` and lists the audiences that may
appear in the token, with `api://AzureADTokenExchange` as the recommended value
([Microsoft Entra Workload Identity Federation Create Trust]). That Entra ID
accepts a TokenRequest-minted token is a derivation: the credential matches on
issuer, subject, and audience, a TokenRequest for the same service account
carries that subject and the requested audience, and Microsoft documents the
exchange only for the projected token. The request is observable as an `AKSAudit
(Kubernetes API server audit)` row; that the row carries `Verb` `create` with
`ObjectRef` resource `serviceaccounts` and subresource `token` is a derivation
from the POST-to-create mapping and the audit event schema, as no page shows a
TokenRequest audit row. The kubelet itself obtains projected service account
tokens through the TokenRequest API ([Kubernetes Service Account
Administration]), so by the same derivation its own TokenRequests would carry
the same verb and object reference.

Either assertion is presented at `/oauth2/v2.0/token` in a client-credentials
token request with the jwt-bearer assertion type, the federated application's
`client_id`, and the target `scope`. An exchange whose federated identity
credential is on an application registration is an `Entra
AADServicePrincipalSignInLogs (Federated credential exchange)` row identified
by `ClientCredentialType` and `FederatedCredentialId`;
`AADManagedIdentitySignInLogs` also carries `FederatedCredentialId`, and the
documented AKS setup federates a user-assigned managed identity, so Microsoft
does not state which table records an exchange whose credential is on a
user-assigned managed identity. The `AADServicePrincipalSignInLogs` `IPAddress`
column is the address of the client used to sign in; by default AKS uses a
Standard Load Balancer for egress through an AKS-assigned public IP, and the
NAT gateway outbound types use Azure NAT Gateway for cluster egress ([Customize
Cluster Egress with Outbound Types in AKS]), so the address that table records
for the exchange is the cluster's egress address rather than the pod's, which
is a derivation from the column definition and the egress configuration. The
credential's `subject` must match the token's `sub` claim ([Microsoft Entra
Workload Identity Federation Considerations]); that a federated identity
credential whose subject names a different namespace or service account
authorizes that account's pods instead follows from that requirement.

![TRR0000.AZR.D DDM](ddms/trr0000_azr_d.png)

## Available Emulation Tests

| ID      | Link                          |
|---------|-------------------------------|
| T1528-1 | [Atomic Test 1 - Blob Upload] |
| T1528-2 | [Atomic Test 2 - File Share]  |

## References

- [RFC 6749 OAuth 2.0 Authorization Framework]
- [RFC 8628 OAuth 2.0 Device Authorization Grant]
- [Microsoft Identity Platform OAuth 2.0 and OpenID Connect Protocols]
- [Microsoft Identity Platform OAuth 2.0 Authorization Code Flow]
- [Microsoft Identity Platform OAuth 2.0 Device Authorization Grant]
- [Microsoft Identity Platform Client Credentials Flow]
- [Microsoft Identity Platform Admin Consent Endpoint]
- [MSAL Authentication Flows]
- [Microsoft Identity Platform Breaking Changes Reference]
- [Microsoft Identity Platform Access Tokens]
- [Microsoft Identity Platform Access Token Claims Reference]
- [Microsoft Identity Platform Configurable Token Lifetimes]
- [Microsoft Identity Web Token Binding]
- [Microsoft Identity Platform Permissions and Consent Overview]
- [Microsoft Entra Application and Delegated Permission Access Tokens]
- [Microsoft Identity Platform Convert App to Multitenant]
- [Microsoft Identity Platform App Manifest Reference]
- [Microsoft Identity Platform Application and Service Principal Objects]
- [Microsoft Identity Platform Publisher Verification Overview]
- [Microsoft Entra Risk-Based Step-Up Consent]
- [Microsoft Entra User and Admin Consent Overview]
- [Microsoft Entra Manage App Consent Policies]
- [Microsoft Entra Grant Tenant-Wide Admin Consent]
- [Microsoft Entra Built-In Roles Reference]
- [Microsoft Graph oAuth2PermissionGrant Resource]
- [Microsoft Graph Service Principal App Role Assignment]
- [Microsoft Graph signIn Resource]
- [Microsoft Entra Conditional Access Authentication Flows]
- [Microsoft Entra Conditional Access Grant Controls]
- [Microsoft Entra Security Defaults]
- [Dynamics 365 Warehouse Management App User-Based Authentication]
- [Microsoft Entra Continuous Access Evaluation]
- [Microsoft Identity Platform Workload Identity Federation]
- [Microsoft Entra Workload Identity Federation Considerations]
- [Microsoft Entra Workload Identity Federation Create Trust]
- [Use Managed Identities on an Azure VM to Acquire Access Tokens]
- [Azure Instance Metadata Service]
- [App Service Managed Identity Overview]
- [App Service Environment Variables and App Settings Reference]
- [Azure Container Apps Managed Identities]
- [Enable Managed Identity for Azure Automation]
- [Service Fabric Managed Identity in Application Code]
- [Azure Container Instances Managed Identity]
- [AKS IMDS Restriction]
- [AKS Managed Identity Overview]
- [Azure SDK Credential Chains]
- [Use Microsoft Entra Workload ID on AKS]
- [Customize Cluster Egress with Outbound Types in AKS]
- [Microsoft Entra Sign-In Logs Overview]
- [Microsoft Entra Interactive User Sign-Ins]
- [Microsoft Entra Non-Interactive User Sign-Ins]
- [Microsoft Entra Service Principal Sign-Ins]
- [Microsoft Entra Managed Identity Sign-Ins]
- [Microsoft Entra Diagnostic Settings Log Options]
- [Azure Monitor SigninLogs Table]
- [Azure Monitor AADNonInteractiveUserSignInLogs Table]
- [Azure Monitor AADServicePrincipalSignInLogs Table]
- [Azure Monitor AADManagedIdentitySignInLogs Table]
- [Azure Monitor AuditLogs Table]
- [Azure Monitor AKSAudit Table]
- [Microsoft Entra Audit Activity Reference]
- [Microsoft Entra Audit Logs for App Permissions]
- [Sysmon]
- [Sysmon Common Event Manifest]
- [Linux auditctl Manual Page]
- [Red Hat Auditing the System]
- [Linux open Manual Page]
- [Linux proc_pid_mem Manual Page]
- [Linux proc_pid_environ Manual Page]
- [Kubernetes Authentication]
- [Kubernetes Service Account Administration]
- [Kubernetes TokenRequest API Reference]
- [Kubernetes Auditing]
- [Kubernetes Audit API Reference]
- [Kubernetes Authorization Overview]
- [Kubernetes RBAC Good Practices]
- [Microsoft Security Blog - Storm-2372 Device Code Phishing]
- [Microsoft Security Blog - AI-Enabled Device Code Phishing 2026]
- [Microsoft Security Blog - CaptiveCrunch]
- [Huntress - Railway PaaS M365 Token Replay Campaign]
- [Sekoia - EvilTokens Device Code Phishing Part 1]
- [Proofpoint - Phishing for Device Code Authorization Account Takeover]
- [Atomic Red Team T1528]

[T1078.004]: https://attack.mitre.org/techniques/T1078/004/
[T1528]: https://attack.mitre.org/techniques/T1528/
[T1550.001]: https://attack.mitre.org/techniques/T1550/001/
[T1552]: https://attack.mitre.org/techniques/T1552/
[T1552.001]: https://attack.mitre.org/techniques/T1552/001/
[AZT203]: https://microsoft.github.io/Azure-Threat-Research-Matrix/InitialAccess/AZT203/AZT203/
[AZT601]: https://microsoft.github.io/Azure-Threat-Research-Matrix/CredentialAccess/AZT601/AZT601/

[Device Authorization Grant Internals]: #device-authorization-grant-internals
[Authorization Code Flow Internals]: #authorization-code-flow-internals
[Client Credentials and Federated Credential Exchange]: #client-credentials-and-federated-credential-exchange
[The Instance Metadata Service]: #the-instance-metadata-service
[OAuth Consent Framework]: #oauth-consent-framework
[Telemetry Surfaces]: #telemetry-surfaces

[RFC 6749 OAuth 2.0 Authorization Framework]: https://datatracker.ietf.org/doc/html/rfc6749
[RFC 8628 OAuth 2.0 Device Authorization Grant]: https://datatracker.ietf.org/doc/html/rfc8628
[Microsoft Identity Platform OAuth 2.0 and OpenID Connect Protocols]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols
[Microsoft Identity Platform OAuth 2.0 Authorization Code Flow]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
[Microsoft Identity Platform OAuth 2.0 Device Authorization Grant]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
[Microsoft Identity Platform Client Credentials Flow]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
[Microsoft Identity Platform Admin Consent Endpoint]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent
[MSAL Authentication Flows]: https://learn.microsoft.com/entra/identity-platform/msal-authentication-flows
[Microsoft Identity Platform Breaking Changes Reference]: https://learn.microsoft.com/entra/identity-platform/reference-breaking-changes
[Microsoft Identity Platform Access Tokens]: https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
[Microsoft Identity Platform Access Token Claims Reference]: https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference
[Microsoft Identity Platform Configurable Token Lifetimes]: https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes
[Microsoft Identity Web Token Binding]: https://learn.microsoft.com/entra/msidweb/call-downstream-apis/token-binding
[Microsoft Identity Platform Permissions and Consent Overview]: https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview
[Microsoft Entra Application and Delegated Permission Access Tokens]: https://learn.microsoft.com/troubleshoot/entra/entra-id/app-integration/application-delegated-permission-access-tokens-identity-platform
[Microsoft Identity Platform Convert App to Multitenant]: https://learn.microsoft.com/entra/identity-platform/howto-convert-app-to-be-multi-tenant
[Microsoft Identity Platform App Manifest Reference]: https://learn.microsoft.com/entra/identity-platform/reference-microsoft-graph-app-manifest
[Microsoft Identity Platform Application and Service Principal Objects]: https://learn.microsoft.com/entra/identity-platform/app-objects-and-service-principals
[Microsoft Identity Platform Publisher Verification Overview]: https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview
[Microsoft Entra Risk-Based Step-Up Consent]: https://learn.microsoft.com/entra/identity/enterprise-apps/configure-risk-based-step-up-consent
[Microsoft Entra User and Admin Consent Overview]: https://learn.microsoft.com/entra/identity/enterprise-apps/user-admin-consent-overview
[Microsoft Entra Manage App Consent Policies]: https://learn.microsoft.com/entra/identity/enterprise-apps/manage-app-consent-policies
[Microsoft Entra Grant Tenant-Wide Admin Consent]: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent
[Microsoft Entra Built-In Roles Reference]: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
[Microsoft Graph oAuth2PermissionGrant Resource]: https://learn.microsoft.com/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0
[Microsoft Graph Service Principal App Role Assignment]: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-approleassignedto?view=graph-rest-1.0
[Microsoft Graph signIn Resource]: https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta
[Microsoft Entra Conditional Access Authentication Flows]: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows
[Microsoft Entra Conditional Access Grant Controls]: https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-grant
[Microsoft Entra Security Defaults]: https://learn.microsoft.com/entra/fundamentals/security-defaults
[Dynamics 365 Warehouse Management App User-Based Authentication]: https://learn.microsoft.com/dynamics365/supply-chain/warehousing/warehouse-app-authenticate-user-based
[Microsoft Entra Continuous Access Evaluation]: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation
[Microsoft Identity Platform Workload Identity Federation]: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
[Microsoft Entra Workload Identity Federation Considerations]: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations
[Microsoft Entra Workload Identity Federation Create Trust]: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust
[Use Managed Identities on an Azure VM to Acquire Access Tokens]: https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token
[Azure Instance Metadata Service]: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
[App Service Managed Identity Overview]: https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity
[App Service Environment Variables and App Settings Reference]: https://learn.microsoft.com/en-us/azure/app-service/reference-app-settings
[Azure Container Apps Managed Identities]: https://learn.microsoft.com/en-us/azure/container-apps/managed-identity
[Enable Managed Identity for Azure Automation]: https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation
[Service Fabric Managed Identity in Application Code]: https://learn.microsoft.com/en-us/azure/service-fabric/how-to-managed-identity-service-fabric-app-code
[Azure Container Instances Managed Identity]: https://learn.microsoft.com/en-us/azure/container-instances/container-instances-managed-identity
[AKS IMDS Restriction]: https://learn.microsoft.com/en-us/azure/aks/imds-restriction
[AKS Managed Identity Overview]: https://learn.microsoft.com/en-us/azure/aks/managed-identity-overview
[Azure SDK Credential Chains]: https://learn.microsoft.com/en-us/azure/developer/python/sdk/authentication/credential-chains
[Use Microsoft Entra Workload ID on AKS]: https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview
[Customize Cluster Egress with Outbound Types in AKS]: https://learn.microsoft.com/en-us/azure/aks/egress-outboundtype
[Microsoft Entra Sign-In Logs Overview]: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
[Microsoft Entra Interactive User Sign-Ins]: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-interactive-sign-ins
[Microsoft Entra Non-Interactive User Sign-Ins]: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins
[Microsoft Entra Service Principal Sign-Ins]: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-service-principal-sign-ins
[Microsoft Entra Managed Identity Sign-Ins]: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-managed-identity-sign-ins
[Microsoft Entra Diagnostic Settings Log Options]: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-diagnostic-settings-logs-options
[Azure Monitor SigninLogs Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
[Azure Monitor AADNonInteractiveUserSignInLogs Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs
[Azure Monitor AADServicePrincipalSignInLogs Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs
[Azure Monitor AADManagedIdentitySignInLogs Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs
[Azure Monitor AuditLogs Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs
[Azure Monitor AKSAudit Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aksaudit
[Microsoft Entra Audit Activity Reference]: https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities
[Microsoft Entra Audit Logs for App Permissions]: https://learn.microsoft.com/entra/identity/enterprise-apps/app-perms-audit-logs
[Sysmon]: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
[Sysmon Common Event Manifest]: https://raw.githubusercontent.com/microsoft/SysmonCommon/main/manifest.xml
[Linux auditctl Manual Page]: https://man7.org/linux/man-pages/man8/auditctl.8.html
[Red Hat Auditing the System]: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening
[Linux open Manual Page]: https://man7.org/linux/man-pages/man2/open.2.html
[Linux proc_pid_mem Manual Page]: https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html
[Linux proc_pid_environ Manual Page]: https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html
[Kubernetes Authentication]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
[Kubernetes Service Account Administration]: https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
[Kubernetes TokenRequest API Reference]: https://raw.githubusercontent.com/kubernetes/website/release-1.34/content/en/docs/reference/kubernetes-api/authentication-resources/token-request-v1.md
[Kubernetes Auditing]: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
[Kubernetes Audit API Reference]: https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
[Kubernetes Authorization Overview]: https://kubernetes.io/docs/reference/access-authn-authz/authorization/
[Kubernetes RBAC Good Practices]: https://kubernetes.io/docs/concepts/security/rbac-good-practices/
[Microsoft Security Blog - Storm-2372 Device Code Phishing]: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
[Microsoft Security Blog - AI-Enabled Device Code Phishing 2026]: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/
[Microsoft Security Blog - CaptiveCrunch]: https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
[Huntress - Railway PaaS M365 Token Replay Campaign]: https://www.huntress.com/blog/railway-paas-m365-token-replay-campaign
[Sekoia - EvilTokens Device Code Phishing Part 1]: https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1
[Proofpoint - Phishing for Device Code Authorization Account Takeover]: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover
[Atomic Red Team T1528]: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1528
[Atomic Test 1 - Blob Upload]: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1528
[Atomic Test 2 - File Share]: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1528
