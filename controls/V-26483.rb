# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-26483' do
  title "The Deny log on as a batch job user right on member servers must be
  configured to prevent access from highly privileged domain accounts on domain
  systems, and from unauthenticated access on all systems."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Deny log on as a batch job\" user right defines accounts that are
  prevented from logging on to the system as a batch job such, as Task Scheduler.


  In an Active Directory Domain, denying logons to the Enterprise Admins and
  Domain Admins groups on lower-trust systems helps mitigate the risk of
  privilege escalation from credential theft attacks which could lead to the
  compromise of an entire domain.

  The Guests group must be assigned to prevent unauthenticated access.
  "
  impact 0.5
  tag "gtitle": 'Deny log on as a batch job'
  tag "gid": 'V-26483'
  tag "rid": 'SV-51502r1_rule'
  tag "stig_id": 'WN12-UR-000018-MS'
  tag "fix_id": 'F-44652r1_fix'
  tag "cci": ['CCI-000213']
  tag "cce": ['CCE-25215-5']
  tag "nist": %w[AC-3 Rev_4]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If the following accounts or groups are not defined for the \"Deny log on as a
  batch job\" user right, this is a finding:

  Domain Systems Only:
  Enterprise Admins Group
  Domain Admins Group

  All Systems:
  Guests Group"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Deny log on as a batch job\" to include the following:

  Domain Systems Only:
  Enterprise Admins Group
  Domain Admins Group

  All Systems:
  Guests Group"

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    describe security_policy do
      its('SeDenyBatchLogonRight') { should eq ['S-1-5-32-546'] }
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
          its('SeDenyRemoteInteractiveLogonRight') { should include "#{domain_admin_sid}" }
       end
       describe security_policy do
          its('SeDenyRemoteInteractiveLogonRight') { should include "#{enterprise_admin_sid}" }
       end
    end
end
