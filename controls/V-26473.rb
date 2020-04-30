# frozen_string_literal: true

control 'V-26473' do
  title "The Allow log on through Remote Desktop Services user right must only
  be assigned to the Administrators group and other approved groups."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Allow log on through Remote Desktop Services\" user
  right can access a system through Remote Desktop.
  "
  impact 0.5
  tag "gtitle": 'Allow log on through Remote Desktop Services'
  tag "gid": 'V-26473'
  tag "rid": 'SV-83319r1_rule'
  tag "stig_id": 'WN12-UR-000006-MS'
  tag "fix_id": 'F-74893r1_fix'
  tag "cci": ['CCI-000213']
  tag "cci": ['CCE-24406-1']
  tag "nist": %w[AC-3 Rev_4]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Allow log
  on through Remote Desktop Services\" user right, this is a finding:

  Administrators

  If the system serves the Remote Desktop Services role, the Remote Desktop Users
  group or another more restrictive group may be included.

  Organizations may grant this to other groups, such as more restrictive groups
  with administrative or management functions, if required.  Remote Desktop
  Services access must be restricted to the accounts that require it.  This must
  be documented with the ISSO."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Allow log on through Remote Desktop Services\" to only include the following
  accounts or groups:

  Administrators

  If the system serves the Remote Desktop Services role, the Remote Desktop Users
  group or another more restrictive group may be included.

  Organizations may grant this to other groups, such as more restrictive groups
  with administrative or management functions, if required.  Remote Desktop
  Services access must be restricted to the accounts that require it.  This must
  be documented with the ISSO."

  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { should eq ['S-1-5-32-544'] }
  end
end
