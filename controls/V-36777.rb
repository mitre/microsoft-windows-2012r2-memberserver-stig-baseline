control "V-36777" do
  title "Toast notifications to the lock screen must be turned off."
  desc  "Toast notifications that are displayed on the lock screen could
  display sensitive information to unauthorized personnel.  Turning off this
  feature will limit access to the information to a logged on user."
  impact 0.3
  tag "gtitle": "WINUC-000006"
  tag "gid": "V-36777"
  tag "rid": "SV-51763r1_rule"
  tag "stig_id": "WN12-UC-000006"
  tag "fix_id": "F-44838r1_fix"
  tag "cci": ["CCE-25414-4", "CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECSC-1"
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_CURRENT_USER
  Registry Path:
  \\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\

  Value Name: NoToastApplicationNotificationOnLockScreen

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for User Configuration ->
  Administrative Templates -> Start Menu and Taskbar -> Notifications -> \"Turn
  off toast notifications on the lock screen\" to \"Enabled\"."
  describe registry_key("HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications") do
    it { should have_property "NoToastApplicationNotificationOnLockScreen" }
    its("NoToastApplicationNotificationOnLockScreen") { should cmp == 1 }
  end
end

