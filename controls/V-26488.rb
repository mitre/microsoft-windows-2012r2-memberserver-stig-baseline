control "V-26488" do
  title "Unauthorized accounts must not have the Force shutdown from a remote
  system user right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Force shutdown from a remote system\" user right can
  remotely shut down a system, which could result in a DoS.
  "
  impact 0.5
  tag "gtitle": "Force shutdown from a remote system"
  tag "gid": "V-26488"
  tag "rid": "SV-53050r1_rule"
  tag "stig_id": "WN12-UR-000023"
  tag "fix_id": "F-45976r1_fix"
  tag "cci": ["CCE-24734-6", "CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Force
  shutdown from a remote system\" user right, this is a finding:

  Administrators"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Force shutdown from a remote system\" to only include the following accounts
  or groups:

  Administrators"
  describe security_policy do
    its("SeRemoteShutdownPrivilege") { should eq ['S-1-5-32-544'] }
  end
end

