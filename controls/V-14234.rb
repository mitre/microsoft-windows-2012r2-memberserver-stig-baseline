control "V-14234" do
  title "User Account Control approval mode for the built-in Administrator must
  be enabled."
    desc  "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting configures the built-in Administrator account so that it runs in
  Admin Approval Mode."
  impact 0.5
  tag "gtitle": "UAC - Admin Approval Mode"
  tag "gid": "V-14234"
  tag "rid": "SV-52946r1_rule"
  tag "stig_id": "WN12-SO-000077"
  tag "fix_id": "F-45872r2_fix"
  tag "cci": ["CCE-24134-9", "CCI-002038"]
  tag "nist": ["CCE-24134-9", "CCI-002038"]
  tag "nist": ["IA-11", "Rev_4"]
  tag "documentable": false
  tag "check": "UAC requirements are NA on Server Core installations.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: FilterAdministratorToken

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "UAC requirements are NA on Server Core installations.

  Configure the policy value for Computer Configuration -> Windows Settings ->
  Security Settings -> Local Policies -> Security Options -> \"User Account
  Control: Admin Approval Mode for the Built-in Administrator account\" to
  \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "FilterAdministratorToken" }
    its("FilterAdministratorToken") { should cmp == 1 }
  end
  only_if do registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('ServerCore', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Mgmt', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Shell', :dword, 1)
  end
end

