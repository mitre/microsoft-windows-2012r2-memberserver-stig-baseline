# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-3456' do
  title "Remote Desktop Services must delete temporary folders when a session
  is terminated."
  desc "Remote desktop session temporary folders must always be deleted after
  a session is over to prevent hard disk clutter and potential leakage of
  information.  This setting controls the deletion of the temporary folders when
  the session is terminated."
  impact 0.5
  tag "gtitle": 'TS/RDS - Delete Temp Folders'
  tag "gid": 'V-3456'
  tag "rid": 'SV-52901r1_rule'
  tag "stig_id": 'WN12-CC-000103'
  tag "fix_id": 'F-45827r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24304-8']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: DeleteTempDirsOnExit

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Temporary Folders -> \"Do not delete temp folder
  upon exit\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'DeleteTempDirsOnExit' }
    its('DeleteTempDirsOnExit') { should cmp == 1 }
  end
end
