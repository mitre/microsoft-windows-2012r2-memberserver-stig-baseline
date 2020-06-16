# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-36712' do
  title "The Windows Remote Management (WinRM) client must not use Basic
  authentication."
  desc "Basic authentication uses plain text passwords that could be used to
  compromise a system."
  impact 0.7
  tag "gtitle": 'WINCC-000123'
  tag "gid": 'V-36712'
  tag "rid": 'SV-51752r1_rule'
  tag "stig_id": 'WN12-CC-000123'
  tag "fix_id": 'F-44827r1_fix'
  tag "cci": ['CCI-000877']
  tag "cce": ['CCE-24431-9']
  tag "nist": ['MA-4 c', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'IAIA-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

  Value Name: AllowBasic

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Windows Remote Management
  (WinRM) -> WinRM Client -> \"Allow Basic authentication\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should cmp == 0 }
  end
end
