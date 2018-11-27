control 'V-36735' do
  title "The system must support automated patch management tools to facilitate
  flaw remediation."
  desc "The organization (including any contractor to the organization) must
  promptly install security-relevant software updates (e.g., patches, service
  packs, hot fixes).  Flaws discovered during security assessments, continuous
  monitoring, incident response activities, or information system error handling
  must also be addressed."
  impact 0.5
  tag "gtitle": 'WINGE-000029'
  tag "gid": 'V-36735'
  tag "rid": 'SV-51583r2_rule'
  tag "stig_id": 'WN12-GE-000024'
  tag "fix_id": 'F-44712r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the organization has an automated process to install
  security-related software updates.  If it does not, this is a finding."
  tag "fix": "Establish a process to automatically install security-related
  software updates."
  describe "The system must support automated patch management tools to facilitate
  flaw remediation." do
    skip 'is a manual check'
  end
end
