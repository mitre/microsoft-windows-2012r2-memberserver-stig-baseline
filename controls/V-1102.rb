control "V-1102" do
  title "Unauthorized accounts must not have the Act as part of the operating
  system user right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Act as part of the operating system\" user right can
  assume the identity of any user and gain access to resources that user is
  authorized to access.  Any accounts with this right can take complete control
  of a system.
  "
  impact 0.7
  tag "gtitle": "User Right - Act as part of OS"
  tag "gid": "V-1102"
  tag "rid": "SV-52108r2_rule"
  tag "stig_id": "WN12-UR-000003"
  tag "fix_id": "F-45133r1_fix"
  tag "cci": ["CCE-25043-1", "CCI-002235"]
  tag "nist": ["CCE-25043-1", "CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": "If an application requires this user
  right, this can be downgraded to a CAT III if the following conditions are met:
  Vendor documentation must support the requirement for having the user right.
  The requirement must be documented with the ISSO.
  The application account must meet requirements for application account
  passwords, such as length (V-36661) and required changes frequency (V-36662)."
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups (to include administrators), are granted the \"Act as
  part of the operating system\" user right, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Act as part of the operating system\" to be defined but containing no entries
  (blank)."
  (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeTcbPrivilege") { should_not include entry }
    end
  end
end

