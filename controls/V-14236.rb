control "V-14236" do
  title "User Account Control must automatically deny standard user requests
  for elevation."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting controls the behavior of elevation when requested by a standard
  user account."
  impact 0.5
  tag "gtitle": "UAC - User Elevation Prompt"
  tag "gid": "V-14236"
  tag "rid": "SV-52948r1_rule"
  tag "stig_id": "WN12-SO-000079"
  tag "fix_id": "F-45874r2_fix"
  tag "cci": ["CCI-002038"]
  tag "cce": ["CCE-24519-1"]
  tag "nist": ["IA-11", "Rev_4"]
  tag "documentable": false
  tag "check": "UAC requirements are NA on Server Core installations.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: ConsentPromptBehaviorUser
 
  Value Type: REG_DWORD
  Value: 0"
  tag "fix": "UAC requirements are NA on Server Core installations.

  Configure the policy value for Computer Configuration -> Windows Settings ->
  Security Settings -> Local Policies -> Security Options -> \"User Account
  Control: Behavior of the elevation prompt for standard users\" to
  \"Automatically deny elevation requests\"."
  if (registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('ServerCore', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Mgmt', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Shell', :dword, 1))
    impact 0.0
    describe "This system is a Server Core Installation, control is NA" do
      skip "This system is a Server Core Installation control is NA"
    end
  else
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
      it { should have_property "ConsentPromptBehaviorUser" }
      its("ConsentPromptBehaviorUser") { should cmp == 0 }
    end
  end
end

