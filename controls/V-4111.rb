control "V-4111" do
  title "The system must be configured to prevent Internet Control Message
  Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)
  generated routes."
  desc  "Allowing ICMP redirect of routes can lead to traffic not being routed
  properly.  When disabled, this forces ICMP to be routed via shortest path
  first."
  impact 0.3
  tag "gtitle": "Disable ICMP Redirect"
  tag "gid": "V-4111"
  tag "rid": "SV-52925r1_rule"
  tag "stig_id": "WN12-SO-000039"
  tag "fix_id": "F-45851r2_fix"
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24977-1']
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

  Value Name: EnableICMPRedirect

  Value Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"MSS:
  (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes\"
  to \"Disabled\".

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'EnableICMPRedirect' }
    its('EnableICMPRedirect') { should cmp == 0 }
  end
end

