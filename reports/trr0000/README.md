# Entra ID Federated Domain Trust Modification

## Metadata

| Key          | Value                              |
|--------------|------------------------------------|
| ID           | TRR0000                            |
| External IDs | [T1484.002], [T1556.007]           |
| Tactics      | Persistence, Defense Evasion       |
| Platforms    | Azure                              |
| Contributors | Andrew VanVleet                    |

### Scope Statement

This TRR covers the modification of Microsoft Entra ID federated domain trust
configuration to register an attacker-controlled token-signing certificate. The
modified trust enables the attacker's identity provider (IdP) to issue signed
identity tokens that Entra accepts as valid for any user in the tenant.

The technique operates entirely against Entra ID's cloud-side configuration. It
does not require compromise of any on-premises identity infrastructure (such as
AD FS), and the attacker's IdP is hosted on attacker-controlled infrastructure.

The use of a valid signing certificate to generate a SAML token is referred to
as a 'Golden SAML' attack ([T1606.002]).[^1] This technique is one of the ways
an attacker can position themselves for a Golden SAML attack in an Azure tenant.

This technique maps to two MITRE ATT&CK IDs:

- T1484.002 Domain or Tenant Policy Modification: Trust Modification, which
  includes modifications to federated domains.
- T1556.007 Modify Authenication Process: Hybrid Identity, which includes trust
  relationships between AD FS and Entra ID.

## Technique Overview

An attacker who holds the required privileges in Entra can modify the tenant's
federated domain configuration to register an attacker-controlled token-signing
certificate. The modified domain trust authorizes the attacker's IdP to issue
signed tokens that Entra accepts. Because federation trust in Entra is
tenant-wide, a single modified domain enables the attacker to authenticate as
any user in the tenant without knowing those users' credentials. This technique
was employed for persistence in the SolarWinds (APT29) and Octo Tempest
intrusion campaigns.

## Technical Background

### Federation in Entra ID

A federated domain delegates authentication to an external identity provider.
When a user with a User Principal Name (UPN) from the federated domain attempts
to sign in, Entra redirects them to the IdP's sign-in URL. The IdP authenticates
the user and returns a signed token (using either the SAML or WS-Federation
protocols). Entra validates the token's signature against the public certificate
stored in the domain's federation configuration. If the signature is valid and
the token corresponds to a user in the tenant the user is signed in.

You can view custom and federated domains in an Entra tenant by using the
`Get-MgDomain` and `Get-MgDomainFederationConfiguration` PowerShell cmdlets
(part of the Microsoft.Graph module).

### Per-domain Redirection, Tenant-wide Trust

Federation in Entra has two distinct scopes that operate independently:

#### Per-domain Sign-in Redirection

When a user attempts an interactive sign-in with a UPN in a federated domain
(e.g., `alice@contoso.com`), Entra redirects that user to the IdP configured for
`contoso.com`. Users in other domains within the same tenant are not redirected
to that IdP, they are redirected to whichever IdP their own domain is federated
with, or if their domain is `Managed` they authenticate against Entra directly.

#### Tenant-wide Token Issuing Trust

Once an IdP is registered as the federation provider for a domain in the tenant,
Entra will trust signed tokens from that IdP for any user in the tenant. When a
token is submitted to Entra, the signature is validated against the federation
configurations registered in the tenant - any registered IdP's certificate is
acceptable. The user is then identified by matching the token's `NameId` claim
to an `ImmutableId` in Entra, with no constraint that the user belong to the
federated domain the token came from.

There is no check that links a token's issuing IdP to the domain of the user
being authenticated. The domain on the federation configuration controls only
*redirection during interactive sign-in*; it does not constrain *which users the
IdP can vouch for* via direct token submission. An attacker who federates a
domain they own (e.g., `attacker-evil-corp.com`) can forge tokens for any user
in that tenant even though the attacker's domain has no relationship to those
users.

This includes:

- Users in other federated domains (whose own domain federates to a different
  IdP)
- Users in `Managed` (non-federated) domains
- Cloud-only users (`@<tenant>.onmicrosoft.com`) who have an `ImmutableId`
- External / guest users who have an `ImmutableId`

>[!NOTE]
>
> Not all Entra users have an `ImmutableId` by default. For users synced from
> on-premises Active Directory, `ImmutableId` is populated automatically and
> corresponds to the on-prem object's `objectGUID` (or a configured anchor). For
> cloud-only and guest users, the attribute is `null` by default. Attackers have
> worked around this limitation by manually adding an `ImmutableId` to a
> cloud-only user (often a high-privilege one). This requires
> `User.ReadWrite.All` permissions, typically held by `User Administrator`,
> `Global Administrator`, etc. It can be done via the MS Graph cmdlet
> `Update-MgUser -UserId "user@yourdomain.com" -OnPremisesImmutableId
> "Base64StringValue=="`

### Federation configuration object

A federated domain's configuration includes the following fields:

- `IssuerUri` - identifier of the IdP. Must match the `Issuer` claim in
  tokens.
- `PassiveSignInUri` / `ActiveSignInUri` - where Entra redirects
  users for interactive sign-in.
- `SignOutUri` - where Entra redirects users on sign-out.
- `SigningCertificate` - base64-encoded X.509 public certificate used to
  verify token signatures.
- `NextSigningCertificate` - secondary certificate slot supporting
  certificate rollover. Tokens signed by this certificate are also accepted by
  Entra.
- `PreferredAuthenticationProtocol` - `wsfed` or `saml`.
- `federatedIdpMfaBehavior` - controls whether Entra accepts MFA claims
  from the federated IdP.

### Domain lifecycle in Entra

A custom domain progresses through a defined lifecycle in Entra:

1. **Add custom domain** - registers the domain string in the tenant. Status
   is set to unverified.
2. **Verify domain** - the requestor publishes a TXT or MX record at the DNS
   authority for the domain; Entra queries DNS for the record and, on success,
   marks the domain verified.
3. **Set domain authentication** - changes the authentication type from
   Managed (the default) to Federated.
4. **Set federation settings on domain** - writes the federation configuration
   (signing certificate, issuer URI, sign-in URIs, etc.) to the domain.

For a domain that is already federated, only step 4 is required to modify the
configuration.

> [!NOTE]
>
> Since spring 2020, Entra has enforced that federation configuration cannot be
> applied to an unverified domain. Prior to that fix, attackers could federate
> any unverified domain string - including domains they did not own - via tools
> like AADInternals' `New-AADIntBackdoor`. Legacy unverified domains may still
> exist in tenants and warrant review.

### Required permissions

The Entra role permissions relevant to this technique are:

- `microsoft.directory/domains/allProperties/allTasks` - grants broad domain
  management permissions, including adding and verifying a domain.
- `microsoft.directory/domains/federation/update` - grants permission to modify
  federation configuration settings

These are held by the following built-in roles:

| Built-in Role | Manage Domains | Update Federation |
| --- | --- | --- |
| Global Administrator | X | X |
| Hybrid Identity Administrator | X | X |
| Partner Tier 2 Support | X | X |
| Domain Name Administrator | X | |
| External Identity Provider Administrator | | X |

### API surfaces

Three API surfaces have historically been usable for this technique, but only
one remains available.

- **MS Graph** - Used by `Update-MgDomainFederationConfiguration` and
  `New-MgDomainFederationConfiguration`.
- **Azure AD Graph** - Retired June 2025. Used by AADInternals.
- **MSOnline V1 Provisioning API** - Retired March 2024. Used by MSOnline's
  `Set-MsolDomainAuthentication`.

### Telemetry

Entra Audit Logs record the following operations relevant to this technique:

- `Add unverified domain` - generated when a new custom domain is added
- `Verify domain` - generated when a domain is successfully verified
- `Set domain authentication` - generated when a domain's authentication type is
  changed (options are 'Managed' and 'Federated')
- `Set federation settings on domain` - generated when a domain's federation
  configuration is created or modified

Each event records the actor, timestamp, target domain, and outcome. Notably,
the `Set federation settings on domain` event does not include the actual
federation configuration values (issuer URI, signing certificate, sign-in URIs)
in the event payload. To recover the configuration that was set, the current
configuration must be queried from MS Graph after the event fires.

## Procedures

| ID | Title | Tactic |
| --- | --- | --- |
| TRR0000.AZR.A | Modify existing federated domain | Persistence, Defense Evasion |
| TRR0000.AZR.B | Add new federated domain | Persistence, Defense Evasion |

### Procedure A: Modify Existing Federated Domain

This procedure applies when the tenant already has a verified domain configured
for federation. The attacker modifies the configuration of the existing domain
to register an attacker-controlled signing certificate. The write can replace
the primary `SigningCertificate` or populate the `NextSigningCertificate` slot.
Populating `NextSigningCertificate` leaves the legitimate signing certificate
intact and operational, so normal user sign-ins continue to succeed while the
attacker's tokens are also accepted.

#### Detection Data Model

![DDM - Modify existing federated domain](ddms/TRR0000_azr_a.png)

The procedure consists of a single essential operation: modifying the federation
configuration of a verified, federated target domain.

### Procedure B: Add New Federated Domain

Under this procedure, an attacker adds a new federated domain to Entra. The
attacker uses a domain they control (or a domain whose DNS they have
compromised). They publish the verification TXT or MX record at the DNS
authority for the domain and then invoke verification, which Entra confirms via
DNS query. With the domain verified, the attacker changes its authentication
type to 'Federated' and writes the federation configuration with their own
signing certificate, allowing them to generate tokens for all users in the
tenant.

This procedure has the same terminal operation as Procedure A but adds three
preceeding operations - adding the domain, verifying it, and setting the
authentication type. (Publishing the DNS record needed to verify the domain
occurs at the attacker's DNS authority and is not observable from within the
victim's Entra tenant.)

The new domain does not need to resemble or relate to any existing domain in the
tenant. Because federation trust is tenant-wide, an arbitrarily-named attacker
domain is sufficient to enable token forgery for any user in the tenant.

#### Detection Data Model

![DDM - Add and federate new domain](ddms/TRR0000_azr_b.png)

The `Publish DNS Record` prerequisite is shown in gray to indicate that it
occurs at an external location and is not observable from within the tenant.

## Available Emulation Tests

| ID            | Link |
|---------------|------|
| TRR0000.AZR.A |      |
| TRR0000.AZR.B |      |

## References

- [Add and verify custom domain names - Microsoft Learn]
- [Add your custom domain - Microsoft Learn]
- [Microsoft Entra built-in roles - Microsoft Learn]
- [Monitor changes to federation configuration in Microsoft Entra ID - Microsoft Learn]
- [Deep-dive to Azure Active Directory Identity Federation - AADInternals]
- [Security vulnerability in Azure AD & Office 365 identity federation - AADInternals]
- [How to create a backdoor to Azure AD - part 1: Identity federation - AADInternals]
- [Roles Allowing To Abuse Entra ID Federation for Persistence and Privilege Escalation - Tenable]
- [I Spy: Escalating to Entra ID Global Admin - Datadog Security Labs]
- [Octo Tempest crosses boundaries to facilitate extortion, encryption, and destruction - Microsoft]
- [Remediation and hardening strategies for Microsoft 365 to defend against APT29 - Mandiant]
- [Detecting Microsoft 365 and Azure Active Directory backdoors - Mandiant]
- [AADInternals FederatedIdentityTools - GitHub]

[^1]: [Golden SAML Attack - CyberArk]

[T1484.002]: https://attack.mitre.org/techniques/T1484/002/
[T1556.007]: https://attack.mitre.org/techniques/T1556/007/
[T1606.002]: https://attack.mitre.org/techniques/T606/002/

[Add and verify custom domain names - Microsoft Learn]: https://learn.microsoft.com/en-us/entra/identity/users/domains-manage
[Add your custom domain - Microsoft Learn]: https://learn.microsoft.com/en-us/entra/fundamentals/add-custom-domain
[Microsoft Entra built-in roles - Microsoft Learn]: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
[Monitor changes to federation configuration in Microsoft Entra ID - Microsoft Learn]: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-monitor-federation-changes
[Deep-dive to Azure Active Directory Identity Federation - AADInternals]: https://aadinternals.com/post/aad-deepdive/
[Security vulnerability in Azure AD & Office 365 identity federation - AADInternals]: https://aadinternals.com/post/federation-vulnerability/
[How to create a backdoor to Azure AD - part 1: Identity federation - AADInternals]: https://aadinternals.com/post/aadbackdoor/
[Roles Allowing To Abuse Entra ID Federation for Persistence and Privilege Escalation - Tenable]: https://medium.com/tenable-techblog/roles-allowing-to-abuse-entra-id-federation-for-persistence-and-privilege-escalation-df9ca6e58360
[I Spy: Escalating to Entra ID Global Admin - Datadog Security Labs]: https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/
[Octo Tempest crosses boundaries to facilitate extortion, encryption, and destruction - Microsoft]: https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/
[Remediation and hardening strategies for Microsoft 365 to defend against APT29 - Mandiant]: https://www.mandiant.com/resources/remediation-and-hardening-strategies-microsoft-365-defend-against-apt29-v13
[Detecting Microsoft 365 and Azure Active Directory backdoors - Mandiant]: https://www.mandiant.com/resources/blog/detecting-microsoft-365-azure-active-directory-backdoors
[AADInternals FederatedIdentityTools - GitHub]: https://github.com/Gerenios/AADInternals/blob/master/FederatedIdentityTools.ps1
[Golden SAML Attack - CyberArk]: https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps