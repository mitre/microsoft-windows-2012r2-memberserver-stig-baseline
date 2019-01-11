control "V-26604" do
  title "The Peer Networking Identity Manager service must be disabled if
  installed."
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption."
  impact 0.5
  tag "gtitle": "Peer Networking Identity Manager Service Disabled"
  tag "gid": "V-26604"
  tag "rid": "SV-52238r2_rule"
  tag "stig_id": "WN12-SV-000103"
  tag "fix_id": "F-45253r1_fix"
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24910-2']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": "ECSC-1"
  tag "check": "Verify the Peer Network Identity Manager (p2pimsvc) service is
  not installed or is disabled.

  Run \"Services.msc\".

  If the following is installed and not disabled, this is a finding:

  Peer Networking Identity Manager (p2pimsvc)"
  tag "fix": "Remove or disable the Peer Networking Identity Manager (p2pimsvc)
  service."
  describe.one do
    describe service('p2pimsvc') do
      it { should_not be_installed }
    end
    describe service('p2pimsvc') do
      it { should_not be_enabled }
    end
  end
end

