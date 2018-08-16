control "V-3289" do
  title "Servers must have a host-based Intrusion Detection System."
  desc  "A properly configured host-based Intrusion Detection System provides
  another level of defense against unauthorized access to critical servers.  With
  proper configuration and logging enabled, such a system can stop and/or alert
  for many attempts to gain unauthorized access to resources."
  impact 0.5
  tag "gtitle": "Intrusion Detection System"
  tag "gid": "V-3289"
  tag "rid": "SV-52105r3_rule"
  tag "stig_id": "WN12-GE-000022"
  tag "fix_id": "F-45130r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": "This finding can be downgraded to a CAT
  III, if there is an active JIDS or firewall protecting the network. "
  tag "check": "Determine whether there is a host-based Intrusion Detection
  System on each server.

  If the HIPS component of HBSS is installed and active on the host and the
  Alerts of blocked activity are being logged and monitored, this will meet the
  requirement of this finding.

  A HID device is not required on a system that has the role as the Network
  Intrusion Device (NID). However, this exception needs to be documented with the
  site ISSO.

  If a host-based Intrusion Detection System is not installed on the system, this
  is a finding."
  tag "fix": "Install a host-based Intrusion Detection System on each server."
  describe "Servers must have a host-based Intrusion Detection System" do
    skip "is a manual check"
  end
end

