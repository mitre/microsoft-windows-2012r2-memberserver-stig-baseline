control 'V-26480' do
  title "Unauthorized accounts must not have the Create global objects user
  right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Create global objects\" user right can create objects
  that are available to all sessions, which could affect processes in other
  users' sessions.
  "
  impact 0.5
  tag "gtitle": 'Create global objects'
  tag "gid": 'V-26480'
  tag "rid": 'SV-52114r2_rule'
  tag "stig_id": 'WN12-UR-000013'
  tag "fix_id": 'F-45139r1_fix'
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-23850-1']
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

  If any accounts or groups other than the following are granted the \"Create
  global objects\" user right, this is a finding:

  Administrators
  Service
  Local Service
  Network Service"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Create global objects\" to only include the following accounts or groups:

  Administrators
  Service
  Local Service
  Network Service"
  describe.one do
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-20', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-20', 'S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-20'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-32-544', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-20', 'S-1-5-32-544', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-20', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-20', 'S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-32-544', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-20'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq ['S-1-5-6'] }
    end
    describe security_policy do
      its('SeCreateGlobalPrivilege') { should eq [] }
    end
  end
end
