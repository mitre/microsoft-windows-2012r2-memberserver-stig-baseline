control "V-18010" do
  title "The Debug programs user right must only be assigned to the
Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    Accounts with the \"Debug programs\" user right can attach a debugger to
any process or to the kernel, providing complete access to sensitive and
critical operating system components.  This right is given to Administrators in
the default configuration.
  "
  impact 0.7
  tag "gtitle": "User Right - Debug Programs"
  tag "gid": "V-18010"
  tag "rid": "SV-52115r3_rule"
  tag "stig_id": "WN12-UR-000016"
  tag "fix_id": "F-45140r2_fix"
  ag "cci": ['CCI-002235']
  tag "cce": ['CCE-23648-9']
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

  If any accounts or groups other than the following are granted the \"Debug
  programs\" user right, this is a finding:

  Administrators

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN12-00-000010) and required frequency of changes
  (WN12-00-000011)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Debug programs\" to only include the following accounts or groups:

  Administrators"
  describe security_policy do
    its('SeDebugPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

