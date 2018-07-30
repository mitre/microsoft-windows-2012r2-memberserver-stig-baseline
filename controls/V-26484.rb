control "V-26484" do
  title "The Deny log on as a service user right on member servers must be
  configured to prevent access from highly privileged domain accounts on domain
  systems.  No other groups or accounts must be assigned this right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Deny log on as a service\" user right defines accounts that are
  denied log on as a service.

  In an Active Directory Domain, denying logons to the Enterprise Admins and
  Domain Admins groups on lower-trust systems helps mitigate the risk of
  privilege escalation from credential theft attacks which could lead to the
  compromise of an entire domain.

  Incorrect configurations could prevent services from starting and result in
  a DoS.
  "
  impact 0.5
  tag "gtitle": "Deny log on as service "
  tag "gid": "V-26484"
  tag "rid": "SV-51504r1_rule"
  tag "stig_id": "WN12-UR-000019-MS"
  tag "fix_id": "F-44654r1_fix"
  tag "cci": ["CCE-23117-5", "CCI-000213"]
  tag "nist": ["CCE-23117-5", "CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If the following accounts or groups are not defined for the \"Deny log on as a
  service\" user right on domain-joined systems, this is a finding:

  Enterprise Admins Group
  Domain Admins Group

  If any accounts or groups are defined for the \"Deny log on as a service\" user
  right on non-domain-joined systems, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Deny log on as a service\" to include the following for domain-joined systems:

  Enterprise Admins Group
  Domain Admins Group

  Configure the \"Deny log on as a service\" for nondomain systems to include no
  entries (blank)."

  is_domain = command("wmic computersystem get domain | FINDSTR /V Domain").stdout.strip
  administrator_group = command("net localgroup Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split('\n')
  administrator_domain_group = command("net localgroup Administrators /DOMAIN | Format-List | Findstr /V 'Alias Name Comment Members - command request'").stdout.strip.split('\n')

  if is_domain == 'WORKGROUP'
    describe security_policy do
      its('SeDenyServiceLogonRight') { should eq [''] }
     end   
      
  else  
    get_domain_sid = command("wmic useraccount get sid | FINDSTR /V SID | Select -First 2").stdout.strip
    domain_sid = get_domain_sid[9..40]
    describe security_policy do
      its('SeDenyServiceLogonRight') { should include "S-1-21-#{domain_sid}-512" }
    end  
    describe security_policy do
      its('SeDenyServiceLogonRight') { should include "S-1-21-#{domain_sid}-519" }
    end 
  end
end

