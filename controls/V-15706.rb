control 'V-15706' do
  title "The user must be prompted to authenticate on resume from sleep
  (plugged in)."
  desc "Authentication must always be required when accessing a system.  This
  setting ensures the user is prompted for a password on resume from sleep
  (plugged in)."
  impact 0.5
  tag "gtitle": "Power Mgmt \xE2\x80\x93 Password Wake When Plugged In"
  tag "gid": 'V-15706'
  tag "rid": 'SV-53132r1_rule'
  tag "stig_id": 'WN12-CC-000055'
  tag "fix_id": 'F-46058r1_fix'
  tag "cci": ['CCI-002038']
  tag "cce": ['CCE-23698-4']
  tag "nist": ['IA-11', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

  Value Name: ACSettingIndex

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Power Management -> Sleep Settings ->
  \"Require a password when a computer wakes (plugged in)\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    it { should have_property 'ACSettingIndex' }
    its('ACSettingIndex') { should cmp == 1 }
  end
end
