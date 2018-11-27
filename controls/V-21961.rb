control 'V-21961' do
  title 'All Direct Access traffic must be routed through the internal network.'
  desc  "Routing all Direct Access  traffic through the internal network allows
  monitoring and prevents split tunneling."
  impact 0.3
  tag "gtitle": "Direct Access \xE2\x80\x93 Route Through Internal Network"
  tag "gid": 'V-21961'
  tag "rid": 'SV-53183r1_rule'
  tag "stig_id": 'WN12-CC-000006'
  tag "fix_id": 'F-46109r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-25221-3']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

  Value Name: Force_Tunneling

  Type: REG_SZ
  Value: Enabled"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> Network Connections -> \"Route all
  traffic through the internal network\" to \"Enabled: Enabled State\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition') do
    it { should have_property 'Force_Tunneling' }
    its('Force_Tunneling') { should eq 1 }
  end
end
