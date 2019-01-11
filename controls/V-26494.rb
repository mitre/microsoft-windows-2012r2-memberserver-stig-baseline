control "V-26494" do
  title "The Lock pages in memory user right must not be assigned to any groups
  or accounts."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

      The \"Lock pages in memory\" user right allows physical memory to be
  assigned to processes, which could cause performance issues or a DoS.
  "
  impact 0.5
  tag "gtitle": "Lock pages in memory"
  tag "gid": "V-26494"
  tag "rid": "SV-52119r3_rule"
  tag "stig_id": "WN12-UR-000029"
  tag "fix_id": "F-45144r2_fix"
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-23829-5']
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

  If any accounts or groups are granted the \"Lock pages in memory\" user right,
  this is a finding.

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN12-00-000010) and required frequency of changes
  (WN12-00-000011)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Lock pages in memory\" to be defined but containing no entries (blank)."
  describe security_policy do
    its('SeLockMemoryPrivilege') { should eq [] }
  end
end

