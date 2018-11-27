control 'V-15727' do
  title 'Users must be prevented from sharing files in their profiles.'
  desc  "Allowing users to share files in their profiles may provide
  unauthorized access or result in the exposure of sensitive data."
  impact 0.5
  tag "gtitle": 'User Network Sharing'
  tag "gid": 'V-15727'
  tag "rid": 'SV-53140r2_rule'
  tag "stig_id": 'WN12-UC-000012'
  tag "fix_id": 'F-46066r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24063-0']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_CURRENT_USER
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

  Value Name: NoInPlaceSharing

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for User Configuration ->
  Administrative Templates -> Windows Components -> Network Sharing -> \"Prevent
  users from sharing files within their profile\" to \"Enabled\"."
  describe registry_key('HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoInPlaceSharing' }
    its('NoInPlaceSharing') { should == 1 }
  end
end
