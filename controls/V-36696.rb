# frozen_string_literal: true

control 'V-36696' do
  title "The detection of compatibility issues for applications and drivers
  must be turned off."
  desc "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this feature will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system."
  impact 0.3
  tag "gtitle": 'WINCC-000065'
  tag "gid": 'V-36696'
  tag "rid": 'SV-51737r2_rule'
  tag "stig_id": 'WN12-CC-000065'
  tag "fix_id": 'F-44812r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24560-5']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\AppCompat\\

  Value Name: DisablePcaUI

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Troubleshooting and Diagnostics ->
  Application Compatibility Diagnostics -> \"Detect compatibility issues for
  applications and drivers\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\AppCompat') do
    it { should have_property 'DisablePcaUI' }
    its('DisablePcaUI') { should cmp == 0 }
  end
end
