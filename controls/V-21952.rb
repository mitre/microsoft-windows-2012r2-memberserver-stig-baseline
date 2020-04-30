# frozen_string_literal: true

control 'V-21952' do
  title 'NTLM must be prevented from falling back to a Null session.'
  desc  "NTLM sessions that are allowed to fall back to Null (unauthenticated)
  sessions may gain unauthorized access."
  impact 0.5
  tag "gtitle": 'NTLM NULL Session Fallback'
  tag "gid": 'V-21952'
  tag "rid": 'SV-53177r1_rule'
  tag "stig_id": 'WN12-SO-000062'
  tag "fix_id": 'F-46103r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-25531-5']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\LSA\\MSV1_0\\

  Value Name: allownullsessionfallback

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network security: Allow LocalSystem NULL session fallback\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    it { should have_property 'allownullsessionfallback' }
    its('allownullsessionfallback') { should cmp == 0 }
  end
end
