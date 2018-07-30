control "V-26489" do
  title "Unauthorized accounts must not have the Generate security audits user
  right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Generate security audits\" user right specifies users and processes
  that can generate Security Log audit records, which must only be the system
  service accounts defined.
  "
  impact 0.5
  tag "gtitle": "Generate security audits"
  tag "gid": "V-26489"
  tag "rid": "SV-52116r2_rule"
  tag "stig_id": "WN12-UR-000024"
  tag "fix_id": "F-45141r1_fix"
  tag "cci": ["CCE-24048-1", "CCI-002235"]
  tag "nist": ["CCE-24048-1", "CCI-002235"]
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

  If any accounts or groups other than the following are granted the \"Generate
  security audits\" user right, this is a finding:

  Local Service
  Network Service"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Generate security audits\" to only include the following accounts or groups:

  Local Service
  Network Service"
  a = ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) + ['S-1-5-19'] + ['S-1-5-20']).uniq
  a.each do |entry|
    describe security_policy do
      its("SeAuditPrivilege") { should_not include entry }
    end
  end
end

