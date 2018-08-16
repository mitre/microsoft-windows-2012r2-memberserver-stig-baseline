control "V-26474" do
  title "Unauthorized accounts must not have the back up files and directories
  user right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Back up files and directories\" user right can
  circumvent file and directory permissions and could allow access to sensitive
  data.
  "
  impact 0.5
  tag "gtitle": "Back up files and directories"
  tag "gid": "V-26474"
  tag "rid": "SV-52111r2_rule"
  tag "stig_id": "WN12-UR-000007"
  tag "fix_id": "F-45136r1_fix"
  tag "cci": ["CCE-25380-7", "CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": "If an application requires this user
  right, this can be downgraded to not a finding if the following conditions are
  met:
  Vendor documentation must support the requirement for having the user right.
  The requirement must be documented with the ISSO.
  The application account must meet requirements for application account
  passwords, such as length (V-36661) and required changes frequency (V-36662)."
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Back up
  files and directories\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Back up files and directories\" to only include the following accounts or
  groups:

  Administrators"
  describe security_policy do
    its("SeBackupPrivilege") { should eq ['S-1-5-32-544'] }
  end
end

