control "V-1145" do
  title "Automatic logons must be disabled."
  desc  "Allowing a system to automatically log on when the machine is booted
  could give access to any unauthorized individual who restarts the computer.
  Automatic logon with administrator privileges would give full access to an
  unauthorized individual."
  impact 0.5
  tag "gtitle": "Disable Automatic Logon"
  tag "gid": "V-1145"
  tag "rid": "SV-52107r2_rule"
  tag "stig_id": "WN12-SO-000036"
  tag "fix_id": "F-45132r1_fix"
  tag "cci": ["CCE-24927-6", "CCI-000366"]
  tag "nist": ["CCE-24927-6", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": "If the DefaultName or DefaultDomainName in
  the same registry path contain an administrator account name and the
  DefaultPassword contains a value, this is a CAT I finding."
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

  Value Name: AutoAdminLogon

  Type: REG_SZ
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"MSS:
  (AutoAdminLogon) Enable Automatic Logon (not recommended)\" to \"Disabled\".

  Ensure no passwords are stored in the \"DefaultPassword\" registry value noted
  below:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

  Value Name: DefaultPassword

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "AutoAdminLogon" }
    its("AutoAdminLogon") { should cmp == 0 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "DefaultPassword" }
    its("DefaultPassword") { should cmp == 0 }
  end
end

