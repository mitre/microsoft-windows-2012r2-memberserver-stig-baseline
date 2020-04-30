# frozen_string_literal: true

control 'V-15672' do
  title 'Event Viewer Events.asp links must be turned off.'
  desc  "Viewing events is a function of administrators, who must not access
  the internet with privileged accounts.  This setting will disable Events.asp
  hyperlinks in Event Viewer to prevent links to the internet from within events."
  impact 0.3
  tag "gtitle": 'Event Viewer Events.asp Links'
  tag "gid": 'V-15672'
  tag "rid": 'SV-53017r1_rule'
  tag "stig_id": 'WN12-CC-000033'
  tag "fix_id": 'F-45944r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24235-4']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\EventViewer\\

  Value Name: MicrosoftEventVwrDisableLinks

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Internet Communication Management ->
  Internet Communication settings -> \"Turn off Event Viewer \"Events.asp\"
  links\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EventViewer') do
    it { should have_property 'MicrosoftEventVwrDisableLinks' }
    its('MicrosoftEventVwrDisableLinks') { should cmp == 1 }
  end
end
