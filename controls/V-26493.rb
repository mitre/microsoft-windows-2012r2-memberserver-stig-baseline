control "V-26493" do
  title "Unauthorized accounts must not have the Load and unload device drivers
  user right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Load and unload device drivers\" user right allows device drivers to
  dynamically be loaded on a system by a user.  This could potentially be used to
  install malicious code by an attacker.
  "
  impact 0.5
  tag "gtitle": "Load and unload device drivers"
  tag "gid": "V-26493"
  tag "rid": "SV-53043r1_rule"
  tag "stig_id": "WN12-UR-000028"
  tag "fix_id": "F-45969r1_fix"
  tag "cci": ["CCE-24779-1", "CCI-002235"]
  tag "nist": ["CCE-24779-1", "CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Load and
  unload device drivers\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Load and unload device drivers\" to only include the following accounts or
  groups:

  Administrators"
  a = ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) + (users.where { username == 'Administrators'}.uids.entries + groups.where { name == 'Administrators'}.gids.entries)).uniq
  a.each do |entry|
    describe security_policy do
      its("SeLoadDriverPrivilege") { should_not include entry }
    end
  end
end

