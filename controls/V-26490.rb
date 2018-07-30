control "V-26490" do
  title "Unauthorized accounts must not have the Impersonate a client after
  authentication user right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Impersonate a client after authentication\" user right allows a
  program to impersonate another user or account to run on their behalf.  An
  attacker could potentially use this to elevate privileges.
  "
  impact 0.5
  tag "gtitle": "Impersonate a client after authentication"
  tag "gid": "V-26490"
  tag "rid": "SV-52117r2_rule"
  tag "stig_id": "WN12-UR-000025"
  tag "fix_id": "F-45142r1_fix"
  tag "cci": ["CCE-24477-2", "CCI-002235"]
  tag "nist": ["CCE-24477-2", "CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": "If an application requires this user
  right, this can be downgraded to not a finding if the following conditions are
  met:
  Vendor documentation must support the requirement for having the user right.
  The requirement must be documented with the ISSO.
  The application account must meet requirements for application account
  passwords, such as length (V-36661) and required changes frequency (V-36662)."
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> User Rights Assignment.

  If any accounts or groups other than the following are granted the
  \"Impersonate a client after authentication\" user right, this is a finding:

  Administrators
  Service
  Local Service
  Network Service"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Impersonate a client after authentication\" to only include the following
  accounts or groups:

  Administrators
  Service
  Local Service
  Network Service"
  a = ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) + (users.where { username == 'Administrators'}.uids.entries + groups.where { name == 'Administrators'}.gids.entries) + ['S-1-5-6'] + ['S-1-5-19'] + ['S-1-5-20']).uniq
  a.each do |entry|
    describe security_policy do
      its("SeImpersonatePrivilege") { should_not include entry }
    end
  end
end

