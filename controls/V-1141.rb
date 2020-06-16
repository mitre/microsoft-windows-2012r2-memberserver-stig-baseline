# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-1141' do
  title 'Unencrypted passwords must not be sent to third-party SMB Servers.'
  desc  "Some non-Microsoft SMB servers only support unencrypted (plain text)
  password authentication.  Sending plain text passwords across the network, when
  authenticating to an SMB server, reduces the overall security of the
  environment.  Check with the vendor of the SMB server to see if there is a way
  to support encrypted password authentication."
  impact 0.5
  tag "gtitle": 'Unencrypted Password is Sent to SMB Server.'
  tag "gid": 'V-1141'
  tag "rid": 'SV-52861r2_rule'
  tag "stig_id": 'WN12-SO-000030'
  tag "fix_id": 'F-45787r2_fix'
  tag "cci": ['CCI-000197']
  tag "cce": ['CCE-24751-0']
  tag "nist": ['IA-5 (1) (c)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:
  \\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

  Value Name:  EnablePlainTextPassword

  Value Type:  REG_DWORD
  Value:  0"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  \"Microsoft Network Client: Send unencrypted password to third-party SMB
  servers\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should have_property 'EnablePlainTextPassword' }
    its('EnablePlainTextPassword') { should cmp == 0 }
  end
end
