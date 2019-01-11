control "V-36661" do
  title "Policy must require application account passwords be at least 15
  characters in length."
  desc  "Application/service account passwords must be of sufficient length to
  prevent being easily cracked.  Application/service accounts that are manually
  managed must have passwords at least 15 characters in length."
  impact 0.5
  tag "gtitle": "WIN00-000010-01"
  tag "gid": "V-36661"
  tag "rid": "SV-51579r1_rule"
  tag "stig_id": "WN12-00-000010"
  tag "fix_id": "F-44708r2_fix"
  tag "cci": ["CCI-000205"]
  tag "nist": ['IA-5 (1) (a)', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": "IAIA-1"
  tag "check": "Verify the site has a policy to ensure passwords for manually
  managed application/service accounts are at least 15 characters in length.  If
  such a policy does not exist or has not been implemented, this is a finding."
  tag "fix": "Establish a site policy that requires application/service account
  passwords that are manually managed to be at least 15 characters in length.
  Ensure the policy is enforced."
  describe security_policy do
    its('MinimumPasswordLength') { should be >= 15 }
  end
end

