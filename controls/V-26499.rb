# frozen_string_literal: true

control 'V-26499' do
  title "Unauthorized accounts must not have the Perform volume maintenance
  tasks user right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Perform volume maintenance tasks\" user right can
  manage volume and disk configurations.  They could potentially delete volumes,
  resulting in data loss or a DoS.
  "
  impact 0.5
  tag "gtitle": 'Perform volume maintenance tasks'
  tag "gid": 'V-26499'
  tag "rid": 'SV-53025r1_rule'
  tag "stig_id": 'WN12-UR-000035'
  tag "fix_id": 'F-45951r1_fix'
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-25070-4']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Perform
  volume maintenance tasks\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Perform volume maintenance tasks\" to only include the following accounts or
  groups:

  Administrators"

  describe security_policy do
    its('SeManageVolumePrivilege') { should eq ['S-1-5-32-544'] }
  end
end
