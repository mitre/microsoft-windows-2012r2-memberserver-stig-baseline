control 'V-15696' do
  title 'The Mapper I/O network protocol (LLTDIO) driver must be disabled.'
  desc  "The Mapper I/O network protocol (LLTDIO) driver allows the discovery
  of the connected network and allows various options to be enabled.  Disabling
  this helps protect the system from potentially discovering and connecting to
  unauthorized devices."
  impact 0.5
  tag "gtitle": "Network \xE2\x80\x93 Mapper I/O Driver"
  tag "gid": 'V-15696'
  tag "rid": 'SV-53072r1_rule'
  tag "stig_id": 'WN12-CC-000001'
  tag "fix_id": 'F-45998r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-25156-1']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry values do not exist or are not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\LLTD\\

  Value Name: AllowLLTDIOOndomain
  Value Name: AllowLLTDIOOnPublicNet
  Value Name: EnableLLTDIO
  Value Name: ProhibitLLTDIOOnPrivateNet

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> Link-Layer Topology Discovery -> \"Turn
  on Mapper I/O (LLTDIO) driver\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'AllowLLTDIOOnDomain' }
    its('AllowLLTDIOOnDomain') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'AllowLLTDIOOnPublicNet' }
    its('AllowLLTDIOOnPublicNet') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'EnableLLTDIO' }
    its('EnableLLTDIO') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'ProhibitLLTDIOOnPrivateNet' }
    its('ProhibitLLTDIOOnPrivateNet') { should cmp == 0 }
  end
end
