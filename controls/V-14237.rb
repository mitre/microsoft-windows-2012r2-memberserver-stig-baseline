control "V-14237" do
  title "User Account Control must be configured to detect application
  installations and prompt for elevation."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting requires Windows to respond to application installation requests
  by prompting for credentials."
  impact 0.5
  tag "gtitle": "UAC - Application Installations"
  tag "gid": "V-14237"
  tag "rid": "SV-52949r1_rule"
  tag "stig_id": "WN12-SO-000080"
  tag "fix_id": "F-45875r2_fix"
  tag "cci": ["CCE-24498-8", "CCI-001084"]
  tag "nist": ["SC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "UAC requirements are NA on Server Core installations.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: EnableInstallerDetection

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "UAC requirements are NA on Server Core installations.

  Configure the policy value for Computer Configuration -> Windows Settings ->
  Security Settings -> Local Policies -> Security Options -> \"User Account
  Control: Detect application installations and prompt for elevation\" to
  \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableInstallerDetection" }
    its("EnableInstallerDetection") { should cmp == 1 }
  end
  only_if do registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('ServerCore', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Mgmt', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Shell', :dword, 1)
  end
end

