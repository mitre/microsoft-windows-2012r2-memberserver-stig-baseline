control "V-26494" do
  title "Unauthorized accounts must not have the Lock pages in memory user
  right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Lock pages in memory\" user right allows physical memory  to be
  assigned to processes, which could cause performance issues or a DoS.
  "
  impact 0.5
  tag "gtitle": "Lock pages in memory"
  tag "gid": "V-26494"
  tag "rid": "SV-52119r2_rule"
  tag "stig_id": "WN12-UR-000029"
  tag "fix_id": "F-45144r1_fix"
  tag "cci": ["CCE-23829-5", "CCI-002235"]
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

  If any accounts or groups are granted the \"Lock pages in memory\" user right,
  this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Lock pages in memory\" to be defined but containing no entries (blank)."
  describe security_policy do
    its("SeLockMemoryPrivilege") { should eq [] }
  end
end
