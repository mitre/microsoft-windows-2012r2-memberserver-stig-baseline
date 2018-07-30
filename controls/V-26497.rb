control "V-26497" do
  title "Unauthorized accounts must not have the Modify an object label user
  right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Modify an object label\" user right can change the
  integrity label of an object.  This could potentially be used to execute code
  at a higher privilege.
  "
  impact 0.5
  tag "gtitle": "Modify an object label"
  tag "gid": "V-26497"
  tag "rid": "SV-53033r1_rule"
  tag "stig_id": "WN12-UR-000033"
  tag "fix_id": "F-45958r1_fix"
  tag "cci": ["CCE-24682-7", "CCI-002235"]
  tag "nist": ["CCE-24682-7", "CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups are granted the \"Modify an object label\" user
  right, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Modify an object label\" to be defined but containing no entries (blank)."
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    a.each do |entry|
      describe security_policy do
        its("SeRelabelPrivilege") { should_not include entry }
      end
    end
  end
end
