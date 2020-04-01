control 'V-26503' do
  title "Unauthorized accounts must not have the Replace a process level token
  user right."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Replace a process level token\" user right allows one process or
  service to start another process or service with a different security access
  token.  A user with this right could use this to impersonate another account.
  "
  impact 0.5
  tag "gtitle": 'Replace a process level token'
  tag "gid": 'V-26503'
  tag "rid": 'SV-52121r2_rule'
  tag "stig_id": 'WN12-UR-000039'
  tag "fix_id": 'F-45146r1_fix'
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-24555-5']
  tag "nist": ['AC-6 (10)', 'Rev_4']
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

  If any accounts or groups other than the following are granted the \"Replace a
  process level token\" user right, this is a finding:

  Local Service
  Network Service"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Replace a process level token\" to only include the following accounts or
  groups:

  Local Service
  Network Service"

    describe security_policy do
      its('SeAssignPrimaryTokenPrivilege') { should eq ['S-1-5-19', 'S-1-5-20'] }
    end
end
