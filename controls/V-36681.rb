# frozen_string_literal: true

control 'V-36681' do
  title "Copying of user input methods to the system account for sign-in must
  be prevented."
  desc "Allowing different input methods for sign-in could open different
  avenues of attack.  User input methods must be restricted to those enabled for
  the system account at sign-in."
  impact 0.5
  tag "gtitle": 'WINCC-000048'
  tag "gid": 'V-36681'
  tag "rid": 'SV-51610r1_rule'
  tag "stig_id": 'WN12-CC-000048'
  tag "fix_id": 'F-44731r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24401-2']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Control Panel\\International\\

  Value Name: BlockUserInputMethodsForSignIn

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Locale Services -> \"Disallow copying of
  user input methods to the system account for sign-in\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Control Panel\\International') do
    it { should have_property 'BlockUserInputMethodsForSignIn' }
    its('BlockUserInputMethodsForSignIn') { should cmp == 1 }
  end
end
