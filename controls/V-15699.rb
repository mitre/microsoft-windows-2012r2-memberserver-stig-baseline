control "V-15699" do
  title "The Windows Connect Now wizards must be disabled."
  desc  "Windows Connect Now provides wizards for tasks such as \"Set up a
  wireless router or access point\" and must not be available to users.
  Functions such as these may allow unauthorized connections to a system and the
  potential for sensitive information to be compromised."
  impact 0.5
  tag "gtitle": "Network – Windows Connect Now Wizards "
  tag "gid": "V-15699"
  tag "rid": "SV-53089r1_rule"
  tag "stig_id": "WN12-CC-000013"
  tag "fix_id": "F-46015r2_fix"
  tag "cci": ["CCE-24665-2", "CCI-000381"]
  tag "nist": ["CCE-24665-2", "CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WCN\\UI\\

  Value Name: DisableWcnUi

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> Windows Connect Now -> \"Prohibit access
  of the Windows Connect Now wizards\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\UI") do
    it { should have_property "DisableWcnUi" }
    its("DisableWcnUi") { should cmp == 1 }
  end
end

