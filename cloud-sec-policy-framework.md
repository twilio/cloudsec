## Cloud Security Policy Framework

Many organisations struggle to define Security Policies and Standards for cloud based infrastructure (IaaS) which reduces security risk without impacting development velocity.

This framework outlines high level principles and objectives, with examples for common cloud environments, which can be adopted by organisations of any size as they seek to secure their cloud infrastructure.

Copyright (c) 2016 Twilio Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### 0.1 Principles

This framework is driven by the following principles:

1.  Strong, consistent and ubiquitous resource management and ownership. Metadata should be used to reliably maintain classification, ownership, and security for all assets, including but not limited to accounts, services, systems, credentials, secrets and applications.

2. Cluster, resource and service management through tools with well defined and secure workflows. Services, clusters and resources should be managed through tooling, not manual intervention. These tools should enforce secure deployment and management pipelines.

3. Defence in depth through limiting the ‘blast radius’ at every level of the cluster. Secure and contain at the account, network and service layer to provide a trusted operating environment for applications, protecting and isolating potentially weak services.

4. Complete visibility into production networks, services and actions within the cluster. All actors, subjects and actions should be reliably captured for any action or change in the production cluster.

5. Review, enforce and inspect manually once, automate many times. Do heavy lifting and manual approval of templates and standards initially, then use automated implementation and enforcement. All rules and policies should be automatically enforceable, enforced and reviewed.

### 1.0 Assets and Classifications

Assets are any resource which is used for engineering purposes, they include:
- Accounts
- Credentials and Secrets
- Server Roles
- Firewall Rules or Security Groups
- File Stores and S3 Buckets

**CSPF 1.1** All assets,regardless of their type, should be documented with parsable metadata which is maintained, managed and up to date. Asset owners should review and update metadata regularly. Asset metadata should include:
- Asset Name
- Asset Description and Purpose
- Asset Owner Details (Team Name, Contact etc)
- Security Classification

#### Example Metadata
```
accounts/aws/security-sandbox.json

{
  "accountid": "499701xxxxxx",
  "name": "security-operations",
  "contact": "security-ops@twilio.com",
  "team": "security",
  "escalation": "https://xxx.pagerduty.com/escalation_policies#xxxxx",
  "description": "Extended Description Here",
  "security": "green"
 }
```

#### An Example Classification Scheme

| Security Classification   | Exposure   | Data or System Access   | Criticality   |
|---| --- | --- | --- |
| **Red**   | Internet facing or handling user data    | Direct access to sensitive data   | In the critical path for a key revenue generating service.   |
| **Blue**   | In the path of customer data  |  Access to internal data    | Key engineering/internal service   |
| **Green**    | Internal Service   | No sensitive data access   | Experimental or low risk service   |

### 2.0 Identity and Authentication

Identity and Authentication reliably manage, identify, and verify, users and systems before they are able access or modify any part of the cluster.

**CSPF 2.1** Identities and Access should be derived from a single point of truth, such as a federated identity provider. Users and Access should be managed, where technically feasible, from a single federated control plane.  

```
https://aws.amazon.com/iam/details/manage-federation/
```

### 3.0 Service Credential Management

Service credentials are used by systems to authenticate against each other. For example, these could include:
- Database Credentials
- API Keys

**CSPF 3.1** Static service credentials should be avoided wherever technically feasible. Solutions such as STS Tokens, Temporary IAM Keys and Automated Credential Rotation should be used wherever possible.   
```
http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
```
Where possible, systems should support automated rotation of credentials on servers and clients, such as Database credentials.

**CSPF 3.2** Where used, Static Service Credentials should be documented in metadata as per CSPF 1.1. Additionally, all service credentials, secrets and key material should include in their metadata:
- Credential Generation Date
- Credential Expiration Date
- Scope of Credential Access (Root, Partial, Prod, Test etc)
- Expiry of Credential (if applicable)
- Credential Custodian(s) (If applicable)

```
credentials/aws/security-ops.json

 "credentials":
    [
      {
        "username": "security-ops@twilio.com",
        "scope": "root",
        "custodians": [
          "user1@twilio.com",
          "user2@twilio.com"
        ],
        "credential_generated": "",
        "credential_expires": ""
      }
    ]
```

**CSPF 3.2** All secrets material should be stored in secure credential/secret stores. Secrets should not be packaged or stored in source code repositories.

**CSPF 3.3** Secret material should not be shared by email, chat systems, ticketing, intranet, or any other open system.

**CSPF 3.4** Any credential should be treated as compromised if it has been accessible beyond the scope of approved access at any time. Upon identification of a compromised credential it should be raised as a Security Incident.

### 4.0 IaaS Accounts

**CSPF 4.1** In addition to the requirements of CSPF 1.1, all IaaS account metadata should include the following attributes in metadata:
- Service/Account Name
- Escalation Contact
- Root account username or ID.
- Credential metadata. (See CSPF 2.2)

**CSPF 4.2** IaaS root accounts, or accounts with equivalent permissions, should not be used for day-to-day operations. Any use of the root credential should be logged and raise a security incident for investigation.

```
https://blogs.aws.amazon.com/security/post/Tx3PSPQSN8374D/How-to-Receive-Notifications-When-Your-AWS-Account-s-Root-Access-Keys-Are-Used
```

**CSPF 4.3** A two-man rule should be enforced for root account access. This should be accomplished by separating the password and multi factor access controls into three pieces distributed amongst at least two different custodians within two different areas of the organisation. Each custodian should share their credentials with a designated backup person and store securely.   

**CSPF 4.4** IaaS accounts should not have root access keys provisioned.

```
for account in accounts:
    client = boto3.client(‘iam’, region_name='us-east-1', account[‘key_id’], account[‘key_secret’])

    if client.get_account_summary()['SummaryMap']['AccountAccessKeysPresent'] > 0:
	     # Root Account with Access Keys provisioned
```

**CSPF 4.5** All static access keys should be rotated every 6 months.

```
for account in accounts:
    client = boto3.client(‘iam’, region_name='us-east-1', account[‘key_id’], account[‘key_secret’])

    resource = boto3.resource(‘iam’, region_name='us-east-1', account[‘key_id’], account[‘key_secret’])

    users = client.list_users()['Users']

    for user in users:
	      user_resource = resource.User(user['UserName'])
	      access_key_iterator = list(user_resource.access_keys.all())

        if len(access_key_iterator):
            for key in access_key_iterator:
                if key.create_date < six_months_ago:
      			       # key older than 6 months
```

**CSPF 4.6** All access to IaaS accounts should be protected with at least two-factors of authentication. (MFA)

```
for account in accounts:
    ## CONNECT TO ACCOUNT AND FETCH USER LIST
    for user in users:
	      user_resource = resource.User(user['UserName'])

        mfa = list(user_resource.mfa_devices.all())

        if len(mfa) == 0 and user_resource.password_last_used is not None:
              # IAM USER DOES NOT HAVE MFA ENABLED
```

### 5.0 IaaS Logging

**CSPF 5.1** All CRUD actions to IaaS accounts and infrastructure (ie changes made via AWS API/Console, changes to networking equipment) should be securely logged. Secure logging should be enabled in all accounts for all regions and all services. Logs should be retained for a period of *n* years. Log fidelity should meet company logging standards.

For example:
- All AWS Accounts should have Cloudtrail logging enabled.
- All modifications to DNS Services should be securely logged

Secure logging means logs should be written to a repository for where:
- Delete or overwrite access is only available to the root account.
- Versioning is enabled for all files.
- MFA Delete is enforced.
- Log file validation is enabled.

These logs should also be duplicated to a secondary storage provider.

### 6.0 Account Segregation

**CSPF 6.1** IaaS environments and applications, where technically feasible, should be segregated between multiple accounts. Different security requirements may affect different applications or accounts dependent on their security classification (See CSPF 1.1).

**CSPF 6.2** Network or data connectivity between environments should be avoided where possible, documented, reviewed and approved by an appropriate level of management, and reviewed every 6 months.

### 7.0 IaaS Roles & Permissions (IAM)

**CSPF 7.1** Access policies should be defined using principle of least privilege.

```
https://awspolicygen.s3.amazonaws.com/policygen.html
```

**CSPF 7.2** All IaaS permissions and policies should be centrally maintained. All policies should include the policy owner, last review date, business justification and any relevant approvals.

**CSPF 7.3** Resource and service owners should define acceptable permissions, or actions, against their resources and services, including what level of approvals is required for individual actions.

For example resource owners may allow any other role to create a policy allowing that role or user to publish to a Kinesis stream, but policies allowing read access should be approved by the owner team.

**CSPF 7.4** Asset owners should review and document, on a periodic basis, users authorized to access their resources.

**CSPF 7.5** User roles should enforce separation of duties through functionally isolated roles, which access only to requires functionality. For example roles may include:
- user-ami-generator
- user-network-administrator
- user-iam-sg-admin

**CSPF 7.6** Roles and users should be audited against usage, any permissions assigned but unused over a 90 day period should be removed. Unused policies, users and roles should be disabled or removed.

```
http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html?icmpid=docs_iam_console
```

**CSPF 7.7** An automated fortnightly digest report should be generated, creating Tickets for respective parties to validate and action where required:
- Actions performed against resources, to the resource owner.
- Actions performed by roles, to the role owner.
- Users assigned to roles, to the role owner.
- Users of actions performed by their accounts, to the user.
- Roles assigned to users, to the manager of users.

The recipient of the report should confirm it has been reviewed and necessary action taken, and close the ticket within 5 days.

### 8.0 Virtual Private Clouds and Direct Connect

**CSPF 8.1** All AWS infrastructure should be run from VPC, Classic services should not be used.

**CSPF 8.2** The following high risk ingress/egress traffic should pass through a stateful firewall, capable of traffic logging, inspection and filtering
- User VPN Concentrators
- NATted Internal Subnets
- Direct Connect
- Other ingress/egress points required by management.

**CSPF 8.3** Netflow or VPC Flow, or alternative flow monitoring, monitoring should be enabled for all high risk subnets or networks.


### 9.0 Firewalls and Security Group Configuration

**CSPF 9.1** Default security groups may be used to create a baseline for connectivity for hosts within the cluster, but other inter-role or application communication should be specifically whitelisted.

**CSPF 9.2** All firewall rulesets should be defined and managed centrally.

**CSPF 9.3** Administrative and database ports, including but not limited to, 22, 23, 1433, 1434, 1521, 3306, 3389, 5432 and 5500, should never be exposed outside the VPC or VPN for any host in any environment.

**CSPF 9.4** Security Groups opened to Internet ranges of or greater than /*n* should have approval from appropriate level of management, and have completed and passed a security review.

**CSPF 9.5** Any security group (inbound or outbound) outside the requirements of this Section, should be approved by an appropriate level of management.

**CSPF 9.6** All ingress and egress rules should be documented with metadata, including the nature/owner of the IP or range, business justification of the rule and approval (If required).

### 10.0 Compute and Machine Images

**CSPF 10.1** Machine images available to be deployed in should be registered and documented, including:
- AMI Version
- Base AMI Image used to generate AMI (if applicable)
- AMI Type
- Date of Generation/Release
- Security Patch Delta, with Severity, CVE etc
- Security Priority (Default P3)
- Security Review and Approval (Where required, as per CSPF 11.2)
- Support EOL Date

**CSPF 10.2** Only approved images may be used as base image. Other images should be reviewed and approved by security.

**CSPF 10.3** Only operating systems which will be supported, for the purpose of security patching, for the next 12 months may be used for AMI images.

**CSPF 10.4** New AMIs should be up to date with all security patches and generated every 30 days, or sooner if required by company vulnerability or patching policy.

**CSPF 10.5** Where used, ssh private keys should be centrally managed and deployed to hosts.

**CSPF 10.6** Where used, the authorized_keys file should be placed in a protected directory, where user write access is not available. (eg `/etc/ssh/keys/<username>/.authorized_keys`)

**CSPF 10.7** All volumes storing data classified as attached to ‘red’ or ‘blue’ classified roles should be encrypted at rest.

**CSPF 10.8** Container images and clusters should conform to the following requirements.
Clusters should use a standardized naming convention, and be managed in line with the security classification for that host. Containers should not aggregate IAM or Network access without compensating controls.

**CSPF 10.9** All servers created should retain the following metadata for a period of at least 12 months:
- Server Role Name
- Created By
- Configuration Deviations
- Internal IP
- External IP

**CSPF 10.10** Hosts classified as ‘red’ should run controls which identify suspicious or abnormal behaviour.

### 11.0 Cloud Storage

**CSPF 11.1** As with all cloud resources, file stores, such as S3 buckets should be documented, classified and managed in accordance with the CSPF 1.1.

**CSPF 11.2** Filestores with ‘red’ or ‘blue’ classification should have access logging and versioning enabled.

**CSPF 11.3** Client side encryption should be enabled for all buckets with ‘red’ or ‘blue’ classification. Company specific or KMS keys should be used for all S3 Encryption.

**CSPF 11.4** All internal buckets should be mapped to VPC Endpoints and access should be restricted to VPCs.

**CSPF 11.5** A single S3 Bucket should not store data of differing security classifications.

**CSPF 11.6** All S3 IAM Access should be restricted to encrypted transport mechanisms (VPC Endpoint of TLS/SSL)


### 12.0 Orchestration and Build Tools

**CSPF 12.1** Orchestration tools should authenticate users, and log all operations performed within the tool or production clusters, directly by users or otherwise. This log should include a full audit trail for any deployment into production, including the packages deployed, versions configured and any relevant approvals.

**CSPF 12.2** Server Roles classified as ‘red’ should be protected with Role Based Access Control, restricting deployments, modifications or deletions to authorized User Roles.


### 13.0 Databases

**CSPF 13.1** Every database should have a single service abstraction layer. Access to the database itself should be restricted by firewall rules and access credentials to only that service role.

**CSPF 13.2** Databases should be backed up at least daily, with each backup being logged and tested at least every 30 days.

**CSPF 13.3** Access to database backups should be restricted.

**CSPF 13.4** All ‘red’ databases should be backed up to a multi-cloud and region service protected with the same level of security as the ‘root’ account.

**CSPF 13.5** Backups should be stored for no longer than 30 days.


### 14.0 Host Security

**CSPF 14.1** All host services should run under service accounts with permissions only to resources required by that service. Services should never run as the root account, or with a level of access equivalent to root.

**CSPF 14.2**  Changes to the production cluster should be enabled through approved tools, outside of an incident, production hosts should not be directly accessed over SSH, nor may production hosts configurations be altered outside the orchestration process. Service owners should ensure systems can be deployed and managed through tools, root or sudo access should not be used to operate any service.

**CSPF 14.3** Server Roles which have been classified as ‘red’ should enforce RBAC SSH access restricted to users with a requirement to access as part of their role.

**CSPF 14.4** Root system production access should only be used when absolutely necessary under a declared incident. Any use of sudo or root on any production system should raise a Security Incident to be investigated.

### 15.0 Production Access and VPNs

**CSPF 15.1** Network and logic access to production should require VPN and/or bastion host connectivity, which should be protected by:
- Username and Password
- Second factor of authentication

**CSPF 15.2** Production systems should log all authentication and access requests.

**CSPF 15.3** VPN concentrators, bastion hosts or any other host which proxies traffic should have any IAM permissions approved.

**CSPF 15.4** Bastion hosts should securely log:
All Authentication attempts
Target servers being accessed,
Commands being run on target servers.


### 16.0 Risk Assessment, Security Testing and Auditing

**CSPF 16.1** All policy requirements should be automatically and continuously verified and enforced.

**CSPF 16.2** A Risk Assessment or Threat Model should occur for any major application or infrastructure change. This process should review the scope of the infrastructure, identify high level risks and raise action items to be resolved.

**CSPF 16.3** An audit trail should be created and retained for any change to IaaS Infrastructure for at least 12 months.
