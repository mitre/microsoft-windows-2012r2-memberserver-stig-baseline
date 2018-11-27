control 'V-26492' do
  title "Unauthorized accounts must not have the Increase scheduling priority
  user right."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Increase scheduling priority\" user right can change a
  scheduling priority causing performance issues or a DoS.
  "
  impact 0.5
  tag "gtitle": 'Increase scheduling priority'
  tag "gid": 'V-26492'
  tag "rid": 'SV-52118r2_rule'
  tag "stig_id": 'WN12-UR-000027'
  tag "fix_id": 'F-45143r1_fix'
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-24911-0']
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

  If any accounts or groups other than the following are granted the \"Increase
  scheduling priority\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Increase scheduling priority\" to only include the following accounts or
  groups:

  Administrators"
  describe.one do
    describe security_policy do
      its('SeIncreaseBasePriorityPrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeIncreaseBasePriorityPrivilege') { should eq [] }
    end
  end
end
