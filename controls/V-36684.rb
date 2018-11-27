control 'V-36684' do
  title 'Local users on domain-joined computers must not be enumerated.'
  desc  "The username is one part of logon credentials that could be used to
  gain access to a system.  Preventing the enumeration of users limits this
  information to authorized personnel."
  impact 0.5
  tag "gtitle": 'WINCC-000051'
  tag "gid": 'V-36684'
  tag "rid": 'SV-51611r1_rule'
  tag "stig_id": 'WN12-CC-000051'
  tag "fix_id": 'F-44732r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-23305-6']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\System\\

  Value Name: EnumerateLocalUsers

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Logon -> \"Enumerate local users on
  domain-joined computers\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnumerateLocalUsers' }
    its('EnumerateLocalUsers') { should cmp == 0 }
  end
end
