control "V-14247" do
  title "Passwords must not be saved in the Remote Desktop Client."
  desc  "Saving passwords in the Remote Desktop Client could allow an
  unauthorized user to establish a remote desktop session to another system.  The
  system must be configured to prevent users from saving passwords in the Remote
  Desktop Client."
  impact 0.5
  tag "gtitle": "TS/RDS - Prevent Password Saving"
  tag "gid": "V-14247"
  tag "rid": "SV-52958r1_rule"
  tag "stig_id": "WN12-CC-000096"
  tag "fix_id": "F-45884r1_fix"
  tag "cci": ["CCI-002038"]
  tag "cce": ["CCE-23787-5"]
  tag "nist": ["IA-11", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: DisablePasswordSaving

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Connection Client -> \"Do not allow passwords to be saved\" to
  \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "DisablePasswordSaving" }
    its("DisablePasswordSaving") { should cmp == 1 }
  end
end

