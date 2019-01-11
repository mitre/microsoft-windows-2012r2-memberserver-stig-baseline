control "V-26479" do
  title "The Create a token object user right must not be assigned to any
  groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

      The \"Create a token object\" user right allows a process to create an
  access token. This could be used to provide elevated rights and compromise a
  system.
  "
  impact 0.7
  tag "gtitle": "Create a token object"
  tag "gid": "V-26479"
  tag "rid": "SV-52113r3_rule"
  tag "stig_id": "WN12-UR-000012"
  tag "fix_id": "F-45138r2_fix"
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-23939-2']
  tag "nist": ['AC-6 (10)', 'Rev_4']
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
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups are granted the \"Create a token object\" user right,
  this is a finding.

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN12-00-000010) and required frequency of changes
  (WN12-00-000011)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Create a token object\" to be defined but containing no entries (blank)."
  describe security_policy do
    its('SeCreateTokenPrivilege') { should eq [] }
  end
end

