control "V-4110" do
  title "The system must be configured to prevent IP source routing."
  desc  "Configuring the system to disable IP source routing protects against
  spoofing."
  impact 0.3
  tag "gtitle": "Disable IP Source Routing"
  tag "gid": "V-4110"
  tag "rid": "SV-52924r1_rule"
  tag "stig_id": "WN12-SO-000038"
  tag "fix_id": "F-45850r2_fix"
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24968-0']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

  Value Name: DisableIPSourceRouting

  Value Type: REG_DWORD
  Value: 2"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"MSS:
  (DisableIPSourceRouting) IP source routing protection level (protects against
  packet spoofing)\" to \"Highest protection, source routing is completely
  disabled\".

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should cmp == 2 }
  end
end

