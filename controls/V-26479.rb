# frozen_string_literal: true

control 'V-26479' do
  title "Unauthorized accounts must not have the Create a token object user
  right."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Create a token object\" user right allows a process to create an
  access token. This could be used to provide elevated rights and compromise a
  system.
  "
  impact 0.7
  tag "gtitle": 'Create a token object'
  tag "gid": 'V-26479'
  tag "rid": 'SV-52113r2_rule'
  tag "stig_id": 'WN12-UR-000012'
  tag "fix_id": 'F-45138r1_fix'
  tag "cci": ['CCI-002235']
  tag "cce": ['CCE-23939-2']
  tag "nist": ['AC-6 (10)', 'Rev_4']
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

  If any accounts or groups are granted the \"Create a token object\" user right,
  this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
  \"Create a token object\" to be defined but containing no entries (blank)."

  describe security_policy do
    its('SeCreateTokenPrivilege') { should eq [] }
  end
end
