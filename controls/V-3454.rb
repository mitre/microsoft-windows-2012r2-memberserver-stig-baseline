control 'V-3454' do
  title "Remote Desktop Services must be configured with the client connection
  encryption set to the required level."
  desc "Remote connections must be encrypted to prevent interception of data
  or sensitive information. Selecting \"High Level\" will ensure encryption of
  Remote Desktop Services sessions in both directions."
  impact 0.5
  tag "gtitle": 'TS/RDS - Set Encryption Level'
  tag "gid": 'V-3454'
  tag "rid": 'SV-52899r2_rule'
  tag "stig_id": 'WN12-CC-000100'
  tag "fix_id": 'F-45825r1_fix'
  tag "cci": ['CCI-000068', 'CCI-002890']
  tag "cce": ['CCE-24932-6']
  tag "nist": ['AC-17 (2)', 'Rev_4']
  tag "nist": ['MA-4 (6)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: MinEncryptionLevel

  Type: REG_DWORD
  Value: 3"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Security -> \"Set client connection encryption
  level\" to \"Enabled\" and \"High Level\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'MinEncryptionLevel' }
    its('MinEncryptionLevel') { should cmp == 3 }
  end
end
