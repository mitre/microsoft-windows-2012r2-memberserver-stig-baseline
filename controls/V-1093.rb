control 'V-1093' do
  title 'Anonymous enumeration of shares must be restricted.'
  desc  "Allowing anonymous logon users (null session connections) to list all
  account names and enumerate all shared resources can provide a map of potential
  points to attack the system."
  impact 0.7
  tag "gtitle": 'Anonymous shares are not restricted'
  tag "gid": 'V-1093'
  tag "rid": 'SV-52847r1_rule'
  tag "stig_id": 'WN12-SO-000052'
  tag "fix_id": 'F-45773r1_fix'
  tag "cci": ['CCI-001090']
  tag "cce": ['CCE-24774-2']
  tag "nist": ['SC-4', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: RestrictAnonymous

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network access: Do not allow anonymous enumeration of SAM accounts and
  shares\" to \"Enabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'RestrictAnonymous' }
    its('RestrictAnonymous') { should cmp == 1 }
  end
end
