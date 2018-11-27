control 'V-26578' do
  title 'The Teredo IPv6 transition technology must be disabled.'
  desc  "IPv6 transition technologies, which tunnel packets through other
  protocols, do not provide visibility."
  impact 0.5
  tag "gtitle": 'Teredo State'
  tag "gid": 'V-26578'
  tag "rid": 'SV-52967r1_rule'
  tag "stig_id": 'WN12-CC-000010'
  tag "fix_id": 'F-45893r1_fix'
  tag "cci": ['CCI-000382']
  tag "cce": ['CCE-25571-1']
  tag "nist": ['CM-7 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

  Value Name: Teredo_State

  Type: REG_SZ
  Value: Disabled"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition
  Technologies -> \"Set Teredo State\" to \"Enabled: Disabled State\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition') do
    it { should have_property 'Teredo_State' }
    its('Teredo_State') { should eq 0 }
  end
end
