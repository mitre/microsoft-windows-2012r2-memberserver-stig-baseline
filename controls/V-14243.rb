# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-14243' do
  title 'Administrator accounts must not be enumerated during elevation.'
  desc  "Enumeration of administrator accounts when elevating can provide part
  of the logon information to an unauthorized user.  This setting configures the
  system to always require users to enter in a username and password to elevate a
  running application."
  impact 0.5
  tag "gtitle": 'Enumerate Administrator Accounts on Elevation'
  tag "gid": 'V-14243'
  tag "rid": 'SV-52955r2_rule'
  tag "stig_id": 'WN12-CC-000077'
  tag "fix_id": 'F-45881r2_fix'
  tag "cci": ['CCI-001084']
  tag "cce": ['CCE-24805-4']
  tag "nist": %w[SC-3 Rev_4]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\

  Value Name: EnumerateAdministrators

  Type: REG_DWORD
  Value: 0x00000000 (0)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> Credential User Interface >>
  \"Enumerate administrator accounts on elevation\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI') do
    it { should have_property 'EnumerateAdministrators' }
    its('EnumerateAdministrators') { should cmp == 0 }
  end
end
