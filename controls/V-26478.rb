# frozen_string_literal: true

control 'V-26478' do
  title 'Unauthorized accounts must not have the Create a pagefile user right.'
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Create a pagefile\" user right can change the size of a
  pagefile, which could affect system performance.
  "
  impact 0.5
  tag "gtitle": 'Create a pagefile'
  tag "gid": 'V-26478'
  tag "rid": 'SV-53063r1_rule'
  tag "stig_id": 'WN12-UR-000011'
  tag "fix_id": 'F-45989r1_fix'
  tag "cci": ['CCE-23972-3']
  tag "cce": ['CCE-23972-3']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Create a
  pagefile\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Create a pagefile\" to only include the following accounts or groups:

  Administrators"

  describe security_policy do
    its('SeCreatePagefilePrivilege') { should eq ['S-1-5-32-544'] }
  end
end
