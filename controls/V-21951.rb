# frozen_string_literal: true

control 'V-21951' do
  title "Services using Local System that use Negotiate when reverting to NTLM
  authentication must use the computer identity vs. authenticating anonymously."
  desc "Services using Local System that use Negotiate when reverting to NTLM
  authentication may gain unauthorized access if allowed to authenticate
  anonymously vs. using the computer identity."
  impact 0.5
  tag "gtitle": 'Computer Identity Authentication for NTLM'
  tag "gid": 'V-21951'
  tag "rid": 'SV-53176r1_rule'
  tag "stig_id": 'WN12-SO-000061'
  tag "fix_id": 'F-46102r1_fix'
  tag "cci": ['CCI-000778']
  tag "cce": ['CCE-25508-3']
  tag "nist": %w[IA-3 Rev_4]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\LSA\\

  Value Name: UseMachineId

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network security: Allow Local System to use computer identity for NTLM\" to
  \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'UseMachineId' }
    its('UseMachineId') { should cmp == 1 }
  end
end
