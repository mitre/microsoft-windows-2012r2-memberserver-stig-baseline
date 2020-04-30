# frozen_string_literal: true

control 'V-36776' do
  title 'Notifications from Windows Push Network Service must be turned off.'
  desc  "The Windows Push Notification Service (WNS) allows third-party vendors
  to send updates for toasts, tiles, and badges."
  impact 0.3
  tag "gtitle": 'WINUC-000005'
  tag "gid": 'V-36776'
  tag "rid": 'SV-51762r1_rule'
  tag "stig_id": 'WN12-UC-000005'
  tag "fix_id": 'F-44837r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-25048-0']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_CURRENT_USER
  Registry Path:
  \\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\

  Value Name: NoCloudApplicationNotification

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for User Configuration ->
  Administrative Templates -> Start Menu and Taskbar -> Notifications -> \"Turn
  off notifications network usage\" to \"Enabled\"."

  describe registry_key('HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications') do
    it { should have_property 'NoCloudApplicationNotification' }
    its('NoCloudApplicationNotification') { should cmp == 1 }
  end
end
