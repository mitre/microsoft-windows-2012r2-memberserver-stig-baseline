control 'V-36719' do
  title "The Windows Remote Management (WinRM) service must not allow
  unencrypted traffic."
  desc  "Unencrypted remote access to a system can allow sensitive information
  to be compromised.  Windows remote management connections must be encrypted to
  prevent this."
  impact 0.5
  tag "gtitle": 'WINCC-000127'
  tag "gid": 'V-36719'
  tag "rid": 'SV-51756r2_rule'
  tag "stig_id": 'WN12-CC-000127'
  tag "fix_id": 'F-44831r1_fix'
  tag "cci": ['CCI-002890', 'CCI-003123']
  tag "cce": ['CCE-25102-5']
  tag "nist": ['MA-4 (6)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

  Value Name: AllowUnencryptedTraffic

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Windows Remote Management
  (WinRM) -> WinRM Service -> \"Allow unencrypted traffic\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should cmp == 0 }
  end
end
