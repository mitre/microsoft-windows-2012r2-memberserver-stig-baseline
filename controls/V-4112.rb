control 'V-4112' do
  title "The system must be configured to disable the Internet Router Discovery
  Protocol (IRDP)."
  desc "The Internet Router Discovery Protocol (IRDP) is used to detect and
  configure default gateway addresses on the computer.  If a router is
  impersonated on a network, traffic could be routed through the compromised
  system."
  impact 0.3
  tag "gtitle": 'Disable Router Discovery'
  tag "gid": 'V-4112'
  tag "rid": 'SV-52926r1_rule'
  tag "stig_id": 'WN12-SO-000044'
  tag "fix_id": 'F-45852r2_fix'
  tag "cci": ['CCI-002385']
  tag "cce": ['CCE-23677-8']
  tag "nist": ['SC-5', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

  Value Name: PerformRouterDiscovery

  Value Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"MSS:
  (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway
  addresses (could lead to DoS)\" to \"Disabled\".

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'PerformRouterDiscovery' }
    its('PerformRouterDiscovery') { should cmp == 0 }
  end
end
