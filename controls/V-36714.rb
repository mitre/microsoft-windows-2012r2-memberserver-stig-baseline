control 'V-36714' do
  title "The Windows Remote Management (WinRM) client must not use Digest
  authentication."
  desc "Digest authentication is not as strong as other options and may be
  subject to man-in-the-middle attacks."
  impact 0.5
  tag "gtitle": 'WINCC-000125'
  tag "gid": 'V-36714'
  tag "rid": 'SV-51754r1_rule'
  tag "stig_id": 'WN12-CC-000125'
  tag "fix_id": 'F-44829r1_fix'
  tag "cci": ['CCI-000877']
  tag "cce": ['CCE-25263-5']
  tag "nist": ['MA-4 c', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'IAIA-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

  Value Name: AllowDigest

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Windows Remote Management
  (WinRM) -> WinRM Client -> \"Disallow Digest authentication\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should have_property 'AllowDigest' }
    its('AllowDigest') { should cmp == 0 }
  end
end
