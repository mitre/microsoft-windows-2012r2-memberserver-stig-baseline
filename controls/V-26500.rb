control 'V-26500' do
  title "Unauthorized accounts must not have the Profile single process user
  right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Profile single process\" user right can monitor
  nonsystem processes performance.  An attacker could potentially use this to
  identify processes to attack.
  "
  impact 0.5
  tag "gtitle": 'Profile single process'
  tag "gid": 'V-26500'
  tag "rid": 'SV-53022r1_rule'
  tag "stig_id": 'WN12-UR-000036'
  tag "fix_id": 'F-45948r1_fix'
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-23844-4']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Profile
  single process\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Profile single process\" to only include the following accounts or groups:

  Administrators"
  
    describe security_policy do
      its('SeProfileSingleProcessPrivilege') { should eq ['S-1-5-32-544'] }
    end
end
