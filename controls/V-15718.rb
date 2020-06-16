# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-15718' do
  title "Turning off File Explorer heap termination on corruption must be
  disabled."
  desc "Legacy plug-in applications may continue to function when a File
  Explorer session has become corrupt.  Disabling this feature will prevent this."
  impact 0.3
  tag "gtitle": "Windows Explorer \xE2\x80\x93 Heap Termination"
  tag "gid": 'V-15718'
  tag "rid": 'SV-53137r1_rule'
  tag "stig_id": 'WN12-CC-000090'
  tag "fix_id": 'F-46063r1_fix'
  tag "cci": ['CCI-002385']
  tag "cce": ['CCE-23913-7']
  tag "nist": %w[SC-5 Rev_4]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

  Value Name: NoHeapTerminationOnCorruption

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> File Explorer -> \"Turn off
  heap termination on corruption\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoHeapTerminationOnCorruption' }
    its('NoHeapTerminationOnCorruption') { should cmp == 0 }
  end
end
