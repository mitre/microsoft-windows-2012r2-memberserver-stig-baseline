# frozen_string_literal: true

control 'V-26485' do
  title "The Deny log on locally user right on member servers must be
  configured to prevent access from highly privileged domain accounts on domain
  systems, and from unauthenticated access on all systems."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Deny log on locally\" user right defines accounts that are prevented
  from logging on interactively.

  In an Active Directory Domain, denying logons to the Enterprise Admins and
  Domain Admins groups on lower-trust systems helps mitigate the risk of
  privilege escalation from credential theft attacks which could lead to the
  compromise of an entire domain.

  The Guests group must be assigned this right to prevent unauthenticated
  access.
  "
  impact 0.5
  tag "gtitle": 'Deny log on locally'
  tag "gid": 'V-26485'
  tag "rid": 'SV-51508r2_rule'
  tag "stig_id": 'WN12-UR-000020-MS'
  tag "fix_id": 'F-49929r1_fix'
  tag "cci": ['CCI-000213']
  tag "cce": ['CCE-24460-8']
  tag "nist": %w[AC-3 Rev_4]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If the following accounts or groups are not defined for the \"Deny log on
  locally\" user right, this is a finding:

  Domain Systems Only:
  Enterprise Admins Group
  Domain Admins Group

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from this.

  All Systems:
  Guests Group"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Deny log on locally\" to include the following:

  Domain Systems Only:
  Enterprise Admins Group
  Domain Admins Group

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from this.

  All Systems:
  Guests Group"

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    describe security_policy do
      its('SeDenyInteractiveLogonRight') { should eq ['S-1-5-32-546'] }
    end
  else
    # Until the shell can handle wmic group where name = 'Domain Users' get SID, this is a add input domain_sid with current SID for Domain
    # get_domain_sid = command('wmic useraccount get sid | FINDSTR /V SID | Select -First 2').stdout.strip
    # domain_sid = get_domain_sid[9..40]
    domain_sid = input('domain_sid')
    describe security_policy do
      its('SeDenyInteractiveLogonRight') { should include "S-1-5-21-#{domain_sid}-512" }
    end
    describe security_policy do
      its('SeDenyInteractiveLogonRight') { should include "S-1-5-21-#{domain_sid}-519" }
    end
  end
end
