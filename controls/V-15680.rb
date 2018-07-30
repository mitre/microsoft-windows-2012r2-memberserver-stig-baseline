control "V-15680" do
  title "The classic logon screen must be required for user logons."
  desc  "The classic logon screen requires users to enter a logon name and
  password to access a system.  The simple logon screen or Welcome screen
  displays  usernames for selection, providing part of the necessary logon
  information."
  impact 0.3
  tag "gtitle": "Classic Logon"
  tag "gid": "V-15680"
  tag "rid": "SV-53036r2_rule"
  tag "stig_id": "WN12-CC-000049-MS"
  tag "fix_id": "F-66505r3_fix"
  tag "cci": ["CCE-23460-9", "CCI-000366"]
  tag "nist": ["CCE-23460-9", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the system is a member of a domain, this is NA.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name:  LogonType

  Type:  REG_DWORD
  Value:  0"
  tag "fix": "If the system is a member of a domain, this is NA.

  Configure the policy value for Computer Configuration >> Administrative
  Templates >> System >> Logon >> \"Always use classic logon\" to \"Enabled\"."
  
  is_domain = command("wmic computersystem get domain | FINDSTR /V Domain").stdout.strip
  
  if is_domain == 'WORKGROUP'
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
      it { should have_property "LogonType" }
      its("LogonType") { should cmp == 0 }
    end
  
  else  
    describe 'System is a member of a domain' do
      skip 'The system is a member of a domain, this is NA'
    end
  end

end

