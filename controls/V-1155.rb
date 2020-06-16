# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-1155' do
  title "The Deny access to this computer from the network user right on member
  servers must be configured to prevent access from highly privileged domain
  accounts and local accounts on domain systems, and from unauthenticated access
  on all systems."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Deny access to this computer from the network\" user right defines
  the accounts that are prevented from logging on from the network.

  In an Active Directory Domain, denying logons to the Enterprise Admins and
  Domain Admins groups on lower-trust systems helps mitigate the risk of
  privilege escalation from credential theft attacks which could lead to the
  compromise of an entire domain.

  Local accounts on domain-joined systems must also be assigned this right to
  decrease the risk of lateral movement resulting from credential theft attacks.

  The Guests group must be assigned this right to prevent unauthenticated
  access.
  "
  impact 0.5
  tag "gtitle": 'Deny Access from the Network'
  tag "gid": 'V-1155'
  tag "rid": 'SV-51501r5_rule'
  tag "stig_id": 'WN12-UR-000017-MS'
  tag "fix_id": 'F-77607r2_fix'
  tag "cci": ['CCI-000213']
  tag "cce": ['CCE-24188-5']
  tag "nist": %w[AC-3 Rev_4]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If the following accounts or groups are not defined for the \"Deny access to
  this computer from the network\" user right, this is a finding:

  Domain Systems Only:
  Enterprise Admins group
  Domain Admins group
  \"Local account and member of Administrators group\" or \"Local account\" (see
  Note below)

  All Systems:
  Guests group

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from denying the
  Enterprise Admins and Domain Admins groups.

  Note: Windows Server 2012 R2 added new built-in security groups, \"Local
  account\" and \"Local account and member of Administrators group\". \"Local
  account\" is more restrictive but may cause issues on servers such as systems
  that provide Failover Clustering.
  Microsoft Security Advisory Patch 2871997 adds the new security groups to
  Windows Server 2012."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Deny access to this computer from the network\" to include the following:

  Domain Systems Only:
  Enterprise Admins group
  Domain Admins group
  \"Local account and member of Administrators group\" or \"Local account\" (see
  Note below)

  All Systems:
  Guests group (S-1-5-32-546)

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from denying the
  Enterprise Admins and Domain Admins groups.

  Note: Windows Server 2012 R2 added new built-in security groups, \"Local
  account\" and \"Local account and member of Administrators group\". \"Local
  account\" is more restrictive but may cause issues on servers such as systems
  that provide Failover Clustering.
  Microsoft Security Advisory Patch 2871997 adds the new security groups to
  Windows Server 2012."

 
  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    describe security_policy do
      its('SeDenyNetworkLogonRight') { should include 'S-1-5-32-546' }
    end

  else
    domain_query = <<-EOH
              $group = New-Object System.Security.Principal.NTAccount('Domain Admins')
              $sid = ($group.Translate([security.principal.securityidentifier])).value
              $sid | ConvertTo-Json
              EOH

    domain_admin_sid = json(command: domain_query).params
    enterprise_admin_query = <<-EOH
              $group = New-Object System.Security.Principal.NTAccount('Enterprise Admins')
              $sid = ($group.Translate([security.principal.securityidentifier])).value
              $sid | ConvertTo-Json
              EOH

    enterprise_admin_sid = json(command: enterprise_admin_query).params
       describe security_policy do
        its('SeDenyNetworkLogonRight') { should include "#{domain_admin_sid}" }
       end
       describe security_policy do
        its('SeDenyNetworkLogonRight') { should include "#{enterprise_admin_sid}" }
       end
  end
end
