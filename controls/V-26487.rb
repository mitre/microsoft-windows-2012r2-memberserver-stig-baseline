control "V-26487" do
  title "Unauthorized accounts must not have the Enable computer and user
  accounts to be trusted for delegation user right on member servers."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Enable computer and user accounts to be trusted for delegation\" user
  right allows the \"Trusted for Delegation\" setting to be changed.  This could
  potentially allow unauthorized users to impersonate other users.
  "
  impact 0.5
  tag "gtitle": "Enable accounts to be trusted for delegation"
  tag "gid": "V-26487"
  tag "rid": "SV-51500r1_rule"
  tag "stig_id": "WN12-UR-000022-MS"
  tag "fix_id": "F-44649r1_fix"
  tag "cci": ["CCE-25270-0", "CCI-002235"]
  tag "nist": ["CCE-25270-0", "CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups are granted the \"Enable computer and user accounts
  to be trusted for delegation\" user right, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Enable computer and user accounts to be trusted for delegation\" to be
  defined but containing no entries (blank)."
  (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeEnableDelegationPrivilege") { should_not include entry }
    end
  end
end

