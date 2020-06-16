# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-3380' do
  title "The system must be configured to force users to log off when their
  allowed logon hours expire."
  desc "Limiting logon hours can help protect data by only allowing access
  during specified times.  This setting controls whether or not users are forced
  to log off when their allowed logon hours expire.  If logon hours are set for
  users, this must be enforced."
  impact 0.5
  tag "gtitle": 'Force Logoff When Logon Hours Expire'
  tag "gid": 'V-3380'
  tag "rid": 'SV-52893r1_rule'
  tag "stig_id": 'WN12-SO-000066'
  tag "fix_id": 'F-45819r1_fix'
  tag "cci": ['CCI-001133']
  tag "cce": ['CCE-25367-4']
  tag "nist": %w[SC-10 Rev_4]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Local Policies -> Security Options.

  If the value for \"Network security: Force logoff when logon hours expire\" is
  not set to \"Enabled\", this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network security: Force logoff when logon hours expire\" to \"Enabled\"."

  describe security_policy do
    its('ForceLogoffWhenHourExpire') { should eq 1 }
  end
end
