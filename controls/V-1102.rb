control "V-1102" do
  title "The Act as part of the operating system user right must not be
  assigned to any groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Act as part of the operating system\" user right can
  assume the identity of any user and gain access to resources that user is
  authorized to access.  Any accounts with this right can take complete control
  of a system.
  "
  impact 0.7
  tag "gtitle": "User Right - Act as part of OS"
  tag "gid": "V-1102"
  tag "rid": "SV-52108r3_rule"
  tag "stig_id": "WN12-UR-000003"
  tag "fix_id": "F-45133r2_fix"
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-25043-1']
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

  If any accounts or groups (to include administrators), are granted the \"Act as
  part of the operating system\" user right, this is a finding.

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN12-00-000010) and required frequency of changes
  (WN12-00-000011)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Act as part of the operating system\" to be defined but containing no entries
  (blank)."
  describe security_policy do
    its('SeTcbPrivilege') { should_not include entry }
  end
end

 