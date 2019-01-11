control "V-15705" do
  title "Users must be prompted to authenticate on resume from sleep (on
  battery)."
  desc  "Authentication must always be required when accessing a system.  This
  setting ensures the user is prompted for a password on resume from sleep (on
  battery)."
  impact 0.5
  tag "gtitle": "Power Mgmt – Password Wake on Battery"
  tag "gid": "V-15705"
  tag "rid": "SV-53131r1_rule"
  tag "stig_id": "WN12-CC-000054"
  tag "fix_id": "F-46057r1_fix"
  tag "cci": ['CCI-002038']
  tag "cce": ['CCE-23998-8']
  tag "nist": ['IA-11', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

  Value Name: DCSettingIndex

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Power Management -> Sleep Settings ->
  \"Require a password when a computer wakes (on battery)\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    it { should have_property 'DCSettingIndex' }
    its('DCSettingIndex') { should cmp == 1 }
  end
end

