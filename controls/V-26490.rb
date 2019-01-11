control "V-26490" do
  title "The Impersonate a client after authentication user right must only be
  assigned to Administrators, Service, Local Service, and Network Service."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

      The \"Impersonate a client after authentication\" user right allows a
  program to impersonate another user or account to run on their behalf.  An
  attacker could potentially use this to elevate privileges.
  "
  impact 0.5
  tag "gtitle": "Impersonate a client after authentication"
  tag "gid": "V-26490"
  tag "rid": "SV-52117r3_rule"
  tag "stig_id": "WN12-UR-000025"
  tag "fix_id": "F-45142r2_fix"
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-24477-2']
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

  If any accounts or groups other than the following are granted the
  \"Impersonate a client after authentication\" user right, this is a finding:

  Administrators
  Service
  Local Service
  Network Service

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN12-00-000010) and required frequency of changes
  (WN12-00-000011)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Impersonate a client after authentication\" to only include the following
  accounts or groups:

  Administrators
  Service
  Local Service
  Network Service"
  describe.one do
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-19', 'S-1-5-20', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-19', 'S-1-5-20', 'S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-19', 'S-1-5-20'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-19', 'S-1-5-32-544', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-19', 'S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-19', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-20', 'S-1-5-32-544', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-20', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-19', 'S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-20', 'S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-32-544', 'S-1-5-6'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-19'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-20'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq ['S-1-5-6'] }
    end
    describe security_policy do
      its('SeImpersonatePrivilege') { should eq [] }
    end
  end
end

