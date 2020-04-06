control 'V-3378' do
  title 'The system must be configured to use the Classic security model.'
  desc  "Windows includes two network-sharing security models - Classic and
  Guest only.  With the Classic model, local accounts must be password protected;
  otherwise, anyone can use guest user accounts to access shared system
  resources."
  impact 0.5
  tag "gtitle": 'Sharing and Security Model for Local Accounts'
  tag "gid": 'V-3378'
  tag "rid": 'SV-52891r1_rule'
  tag "stig_id": 'WN12-SO-000060'
  tag "fix_id": 'F-45817r1_fix'
  tag "cci": ['CCI-001090']
  tag "cce": ['CCE-22742-1']
  tag "nist": ['SC-4', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: ForceGuest

  Value Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network access: Sharing and security model for local accounts\" to \"Classic
  - local users authenticate as themselves\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'ForceGuest' }
    its('ForceGuest') { should cmp == 0 }
  end
end
