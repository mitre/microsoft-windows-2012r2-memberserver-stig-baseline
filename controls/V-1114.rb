# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-1114' do
  title 'The built-in guest account must be renamed.'
  desc  "The built-in guest account is a well-known user account on all Windows
  systems and, as initially installed, does not require a password.  This can
  allow access to system resources by unauthorized users.  Renaming this account
  to an unidentified name improves the protection of this account and the system."
  impact 0.5
  tag "gtitle": 'Rename Built-in Guest Account'
  tag "gid": 'V-1114'
  tag "rid": 'SV-52856r1_rule'
  tag "stig_id": 'WN12-SO-000006'
  tag "fix_id": 'F-45782r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-23675-2']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> Security Options.

  If the value for \"Accounts: Rename guest account\" is not set to a value other
  than \"Guest\", this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Accounts: Rename guest account\" to a name other than \"Guest\"."

  describe user('Guest') do
    it { should_not exist }
  end
end
