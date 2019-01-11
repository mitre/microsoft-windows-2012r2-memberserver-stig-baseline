control "V-4113" do
  title "The system must be configured to limit how often keep-alive packets
  are sent."
  desc  "This setting controls how often TCP sends a keep-alive packet in
  attempting to verify that an idle connection is still intact.  A higher value
  could allow an attacker to cause a denial of service with numerous connections."
  impact 0.3
  tag "gtitle": "TCP Connection Keep-Alive Time"
  tag "gid": "V-4113"
  tag "rid": "SV-52927r1_rule"
  tag "stig_id": "WN12-SO-000041"
  tag "fix_id": "F-45853r2_fix"
  tag "cci": ['CCI-002385']
  tag "cce": ['CCE-24310-5']
  tag "nist": ['SC-5', 'Rev_4']
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

  Value Name: KeepAliveTime

  Value Type: REG_DWORD
  Value: 300000 (or less)"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"MSS:
  (KeepAliveTime) How often keep-alive packets are sent in milliseconds\" to
  \"300000 or 5 minutes (recommended)\" or less.

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"
   describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'KeepAliveTime' }
    its('KeepAliveTime') { should cmp <= 300000 }
  end
end

