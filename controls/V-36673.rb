control 'V-36673' do
  title 'IP stateless autoconfiguration limits state must be enabled.'
  desc  "IP stateless autoconfiguration could configure routes that circumvent
  preferred routes if not limited."
  impact 0.3
  tag "gtitle": 'WINCC-000011'
  tag "gid": 'V-36673'
  tag "rid": 'SV-51605r1_rule'
  tag "stig_id": 'WN12-CC-000011'
  tag "fix_id": 'F-44726r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24070-5']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

  Value Name: EnableIPAutoConfigurationLimits

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> TCPIP Settings -> Parameters -> \"Set IP
  Stateless Autoconfiguration Limits State\" to \"Enabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'EnableIPAutoConfigurationLimits' }
    its('EnableIPAutoConfigurationLimits') { should cmp == 1 }
  end
end
