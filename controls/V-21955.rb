control "V-21955" do
  title "IPv6 source routing must be configured to the highest protection
  level."
  desc  "Configuring the system to disable IPv6 source routing protects against
  spoofing."
  impact 0.3
  tag "gtitle": "IPv6 Source Routing"
  tag "gid": "V-21955"
  tag "rid": "SV-53180r2_rule"
  tag "stig_id": "WN12-SO-000037"
  tag "fix_id": "F-46106r1_fix"
  tag "cci": ["CCI-000366"]
  tag "cce": ["CCE-24452-5"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\

  Value Name: DisableIPSourceRouting

  Type: REG_DWORD
  Value: 2"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"MSS:
  (DisableIPSourceRouting IPv6) IP source routing protection level (protects
  against packet spoofing)\" to \"Highest protection, source routing is
  completely disabled\".

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters") do
    it { should have_property "DisableIPSourceRouting" }
    its("DisableIPSourceRouting") { should cmp == 2 }
  end
end

