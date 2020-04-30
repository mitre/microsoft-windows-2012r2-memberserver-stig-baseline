# frozen_string_literal: true

control 'V-26577' do
  title 'The ISATAP IPv6 transition technology must be disabled.'
  desc  "IPv6 transition technologies, which tunnel packets through other
  protocols, do not provide visibility."
  impact 0.5
  tag "gtitle": 'ISATAP State'
  tag "gid": 'V-26577'
  tag "rid": 'SV-52968r1_rule'
  tag "stig_id": 'WN12-CC-000009'
  tag "fix_id": 'F-45894r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-25249-4']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

  Value Name: ISATAP_State

  Type: REG_SZ
  Value: Disabled"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition
  Technologies -> \"Set ISATAP State\" to \"Enabled: Disabled State\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition') do
    it { should have_property 'ISATAP_State' }
    its('ISATAP_State') { should cmp 'Disabled' }
  end
end
