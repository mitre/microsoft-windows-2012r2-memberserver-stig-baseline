# frozen_string_literal: true

control 'V-16048' do
  title 'Windows Help Ratings feedback must be turned off.'
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting ensures users cannot provide ratings feedback to Microsoft for
  Help content.
  "
  impact 0.5
  tag "gtitle": 'Help Ratings'
  tag "gid": 'V-16048'
  tag "rid": 'SV-53145r1_rule'
  tag "stig_id": 'WN12-UC-000008'
  tag "fix_id": 'F-46071r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-25470-6']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_CURRENT_USER
  Registry Path: \\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0\\

  Value Name: NoExplicitFeedback

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for User Configuration ->
  Administrative Templates -> System -> Internet Communication Management ->
  Internet Communication Settings -> \"Turn off Help Ratings\" to \"Enabled\"."

  describe registry_key('HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0') do
    it { should have_property 'NoExplicitFeedback' }
    its('NoExplicitFeedback') { should cmp == 1 }
  end
end
