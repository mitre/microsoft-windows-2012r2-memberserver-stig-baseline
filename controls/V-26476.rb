control 'V-26476' do
  title "Unauthorized accounts must not have the Change the system time user
  right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Change the system time\" user right can change the
  system time, which can impact authentication, as well as affect time stamps on
  event log entries.
  "
  impact 0.5
  tag "gtitle": 'Change the system time'
  tag "gid": 'V-26476'
  tag "rid": 'SV-53118r1_rule'
  tag "stig_id": 'WN12-UR-000009'
  tag "fix_id": 'F-46044r1_fix'
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-24185-1']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Change the
  system time\" user right, this is a finding:

  Administrators
  Local Service"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Change the system time\" to only include the following accounts or groups:

  Administrators
  Local Service"
  
    describe security_policy do
      its('SeTimeZonePrivilege') { should eq ['S-1-5-19', 'S-1-5-32-544'] }
    end
end
