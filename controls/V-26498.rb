control "V-26498" do
  title "Unauthorized accounts must not have the Modify firmware environment
  values user right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Modify firmware environment values\" user right can
  change hardware configuration environment variables.  This could result in
  hardware failures or a DoS.
  "
  impact 0.5
  tag "gtitle": "Modify firmware environment values"
  tag "gid": "V-26498"
  tag "rid": "SV-53029r1_rule"
  tag "stig_id": "WN12-UR-000034"
  tag "fix_id": "F-45955r1_fix"
  tag "cci": ["CCE-25533-1", "CCI-002235"]
  tag "nist": ["CCE-25533-1", "CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Modify
  firmware environment values\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Modify firmware environment values\" to only include the following accounts
  or groups:

  Administrators"
  a = ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) + (users.where { username == 'Administrators'}.uids.entries + groups.where { name == 'Administrators'}.gids.entries)).uniq
  a.each do |entry|
    describe security_policy do
      its("SeSystemEnvironmentPrivilege") { should_not include entry }
    end
  end
end

