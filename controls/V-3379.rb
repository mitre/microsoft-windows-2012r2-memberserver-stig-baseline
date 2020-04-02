control 'V-3379' do
  title "The system must be configured to prevent the storage of the LAN
  Manager hash of passwords."
  desc "The LAN Manager hash uses a weak encryption algorithm and there are
  several tools available that use this hash to retrieve account passwords.  This
  setting controls whether or not a LAN Manager hash of the password is stored in
  the SAM the next time the password is changed."
  impact 0.7
  tag "gtitle": 'LAN Manager Hash stored'
  tag "gid": 'V-3379'
  tag "rid": 'SV-52892r2_rule'
  tag "stig_id": 'WN12-SO-000065'
  tag "fix_id": 'F-45818r1_fix'
  tag "cci": ['CCI-000196']
  tag "cce": ['CCE-24150-5']
  tag "nist": ['SC-6.1', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: NoLMHash

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network security: Do not store LAN Manager hash value on next password
  change\" to \"Enabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'NoLMHash' }
    its('NoLMHash') { should cmp == 1 }
  end
end
