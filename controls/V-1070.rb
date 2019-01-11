control "V-1070" do
  title "Server systems must be located in a controlled access area, accessible
  only to authorized personnel."
  desc  "Inadequate physical protection can undermine all other security
  precautions utilized to protect the system.  This can jeopardize the
  confidentiality, availability, and integrity of the system.  Physical security
  is the first line of protection of any system."
  impact 0.5
  tag "gtitle": "Physical security"
  tag "gid": "V-1070"
  tag "rid": "SV-52838r1_rule"
  tag "stig_id": "WN12-00-000001"
  tag "fix_id": "F-45764r1_fix"
  tag "cci": ["CCI-000366"]
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
  tag "check": "Verify servers are located in controlled access areas that are
  accessible only to authorized personnel.  If systems are not adequately
  protected, this is a finding."
  tag "fix": "Ensure servers are located in secure, access-controlled areas."
  describe 'Server systems must be located in a controlled area' do
    skip 'is a manual check'
  end
end

