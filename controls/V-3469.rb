control "V-3469" do
  title "Group Policies must be refreshed in the background if the user is
  logged on."
  desc  "If this setting is enabled, then Group Policy settings are not
  refreshed while a user is currently logged on.  This could lead to instances
  when a user does not have the latest changes to a policy applied and is
  therefore operating in an insecure context."
  impact 0.5
  tag "gtitle": "Group Policy - Do Not Turn off Background Refresh"
  tag "gid": "V-3469"
  tag "rid": "SV-52906r1_rule"
  tag "stig_id": "WN12-CC-000029"
  tag "fix_id": "F-45832r1_fix"
  tag "cci": ["CCE-23622-4", "CCI-000366"]
  tag "nist": ["CCE-23622-4", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "Review the registry.
  If the following registry value does not exist, this is not a finding (this is
  the expected result from configuring the policy as outlined in the Fix
  section.):
  If the following registry value exists but is not configured as specified, this
  is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\system\\

  Value Name: DisableBkGndGroupPolicy

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Group Policy -> \"Turn off background
  refresh of Group Policy\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\system\\") do
    it { should have_property "DisableBkGndGroupPolicy" }
    its("DisableBkGndGroupPolicy") { should cmp == 0 }
  end
end

