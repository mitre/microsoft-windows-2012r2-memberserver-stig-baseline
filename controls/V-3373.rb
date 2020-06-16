# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-3373' do
  title "The maximum age for machine account passwords must be set to
  requirements."
  desc "Computer account passwords are changed automatically on a regular
  basis.  This setting controls the maximum password age that a machine account
  may have.  This setting must be set to no more than 30 days, ensuring the
  machine changes its password monthly."
  impact 0.3
  tag "gtitle": 'Maximum Machine Account Password Age'
  tag "gid": 'V-3373'
  tag "rid": 'SV-52887r1_rule'
  tag "stig_id": 'WN12-SO-000016'
  tag "fix_id": 'F-45813r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-23596-0']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

  Value Name: MaximumPasswordAge

  Value Type: REG_DWORD
  Value: 30 (or less, but not 0)"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"Domain
  member: Maximum machine account password age\" to \"30\" or less (excluding
  \"0\" which is unacceptable)."

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should have_property 'MaximumPasswordAge' }
    its('MaximumPasswordAge') { should be_between(1,input('comp_acct_max_pass_age')) }
  end
end
