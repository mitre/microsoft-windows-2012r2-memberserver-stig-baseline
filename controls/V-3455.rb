control "V-3455" do
  title "Remote Desktop Services must be configured to use session-specific
  temporary folders."
  desc  "If a communal temporary folder is used for remote desktop sessions, it
  might be possible for users to access other users' temporary folders.  If this
  setting is enabled, only one temporary folder is used for all remote desktop
  sessions.  Per session temporary folders must be established."
  impact 0.5
  tag "gtitle": "TS/RDS - Do Not Use Temp Folders"
  tag "gid": "V-3455"
  tag "rid": "SV-52900r1_rule"
  tag "stig_id": "WN12-CC-000104"
  tag "fix_id": "F-45826r1_fix"
  tag "cci": ["CCI-000366"]
  tag "cce": ["CCE-24042-4"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: PerSessionTempDir

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Temporary Folders -> \"Do not use temporary
  folders per session\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "PerSessionTempDir" }
    its("PerSessionTempDir") { should cmp == 1 }
  end
end

