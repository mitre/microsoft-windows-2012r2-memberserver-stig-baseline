# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-1097' do
  title "The number of allowed bad logon attempts must meet minimum
  requirements."
  desc "The account lockout feature, when enabled, prevents brute-force
  password attacks on the system.  The higher this value is, the less effective
  the account lockout feature will be in protecting the local system.  The number
  of bad logon attempts must be reasonably small to minimize the possibility of a
  successful password attack, while allowing for honest errors made during a
  normal user logon."
  impact 0.5
  tag "gtitle": 'Bad Logon Attempts'
  tag "gid": 'V-1097'
  tag "rid": 'SV-52848r1_rule'
  tag "stig_id": 'WN12-AC-000002'
  tag "fix_id": 'F-45774r1_fix'
  tag "cci": ['CCI-000044']
  tag "cce": ['CCE-23909-5']
  tag "nist": ['AC-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Account Policies -> Account Lockout Policy.

  If the \"Account lockout threshold\" is \"0\" or more than \"3\" attempts, this
  is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
Settings -> Security Settings -> Account Policies -> Account Lockout Policy ->
\"Account lockout threshold\" to \"3\" or less invalid logon attempts
(excluding \"0\" which is unacceptable)."

  describe security_policy do
    its('LockoutBadCount') { should be_between(1,input('max_pass_lockout')) }
  end
end
