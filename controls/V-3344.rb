control "V-3344" do
  title "Local accounts with blank passwords must be restricted to prevent
  access from the network."
  desc  "An account without a password can allow unauthorized access to a
  system as only the username would be required.  Password policies should
  prevent accounts with blank passwords from existing on a system.  However, if a
  local account with a blank password did exist, enabling this setting will
  prevent network access, limiting the account to local console logon only."
  impact 0.7
  tag "gtitle": "Limit Blank Passwords"
  tag "gid": "V-3344"
  tag "rid": "SV-52886r1_rule"
  tag "stig_id": "WN12-SO-000004"
  tag "fix_id": "F-45812r1_fix"
  tag "cci": ["CCE-25589-3", "CCI-000366"]
  tag "nist": ["CCE-25589-3", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: LimitBlankPasswordUse

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Accounts: Limit local account use of blank passwords to console logon only\"
  to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\Currentcontrolset\\Control\\Lsa") do
    it { should have_property "Limitblankpassworduse" }
    its("Limitblankpassworduse") { should cmp == 1 }
  end
end

