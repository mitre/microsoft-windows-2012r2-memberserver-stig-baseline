control "V-26486" do
  title "The Deny log on through Remote Desktop Services user right on member
  servers must be configured to prevent access from highly privileged domain
  accounts and all local accounts on domain systems, and from unauthenticated
  access on all systems."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Deny log on through Remote Desktop Services\" user right defines the
  accounts that are prevented from logging on using Remote Desktop Services.

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
  tag "gtitle": "Deny log on through Remote Desktop \\ Terminal Services"
  tag "gid": "V-26486"
  tag "rid": "SV-51509r4_rule"
  tag "stig_id": "WN12-UR-000021-MS"
  tag "fix_id": "F-74891r2_fix"
  tag "cci": ["CCI-000213"]
  tag "cce": ["CCE-23273-6"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If the following accounts or groups are not defined for the \"Deny log on
  through Remote Desktop Services\" user right, this is a finding:

  Domain Systems Only:
  Enterprise Admins group
  Domain Admins group
  Local account (see Note below)

  All Systems:
  Guests group

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from denying the
  Enterprise Admins and Domain Admins groups.

  Note: Windows Server 2012 R2 added new built-in security groups, including
  \"Local account\", for assigning permissions and rights to all local accounts.
  Microsoft Security Advisory Patch 2871997 adds the new security groups to
  Windows Server 2012."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Deny log on through Remote Desktop Services\" to include the following:

  Domain Systems Only:
  Enterprise Admins group
  Domain Admins group
  Local account (see Note below)

  All Systems:
  Guests group

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from denying the
  Enterprise Admins and Domain Admins groups.

  Note: Windows Server 2012 R2 added new built-in security groups, including
  \"Local account\", for assigning permissions and rights to all local accounts.
  Microsoft Security Advisory Patch 2871997 adds the new security groups to
  Windows Server 2012."
  
  is_domain = command("wmic computersystem get domain | FINDSTR /V Domain").stdout.strip
  administrator_group = command("net localgroup Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split('\n')
  administrator_domain_group = command("net localgroup Administrators /DOMAIN | Format-List | Findstr /V 'Alias Name Comment Members - command request'").stdout.strip.split('\n')

  if is_domain == 'WORKGROUP'
    describe.one do
      describe security_policy do
        its('SeDenyRemoteInteractiveLogonRight') { should eq ['S-1-5-32-546'] }
      end
      describe security_policy do
        its('SeDenyRemoteInteractiveLogonRight') { should eq [] }
      end 
    end   
      
  else  
    get_domain_sid = command("wmic useraccount get sid | FINDSTR /V SID | Select -First 2").stdout.strip
    domain_sid = get_domain_sid[9..40]
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include "S-1-21-#{domain_sid}-512" }
    end  
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include "S-1-21-#{domain_sid}-519" }
    end 
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include 'S-1-2-0' }
    end 
  end
 
end

