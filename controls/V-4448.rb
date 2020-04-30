# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-4448' do
  title "Group Policy objects must be reprocessed even if they have not
  changed."
  desc  "Enabling this setting and then selecting the \"Process even if the
  Group Policy objects have not changed\" option ensures that the policies will
  be reprocessed even if none have been changed.  This way, any unauthorized
  changes are forced to match the domain-based group policy settings again."
  impact 0.5
  tag "gtitle": 'Group Policy - Registry Policy Processing'
  tag "gid": 'V-4448'
  tag "rid": 'SV-52933r1_rule'
  tag "stig_id": 'WN12-CC-000028'
  tag "fix_id": 'F-45859r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24992-0']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Group
  Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\\

  Value Name: NoGPOListChanges

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Group Policy -> \"Configure registry
  policy processing\" to \"Enabled\" and select the option \"Process even if the
  Group Policy objects have not changed\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should have_property 'NoGPOListChanges' }
    its('NoGPOListChanges') { should cmp == 0 }
  end
end
