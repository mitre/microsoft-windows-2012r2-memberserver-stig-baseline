# frozen_string_literal: true

control 'V-2374' do
  title 'Autoplay must be disabled for all drives.'
  desc  "Allowing Autoplay to execute may introduce malicious code to a system.
  Autoplay begins reading from a drive as soon media is inserted into the drive.
  As a result, the setup file of programs or music on audio media may start.  By
  default, Autoplay is disabled on removable drives, such as the floppy disk
  drive (but not the CD-ROM drive) and on network drives.  Enabling this policy
  disables Autoplay on all drives."
  impact 0.7
  tag "gtitle": 'Disable Media Autoplay'
  tag "gid": 'V-2374'
  tag "rid": 'SV-52879r2_rule'
  tag "stig_id": 'WN12-CC-000074'
  tag "fix_id": 'F-45805r1_fix'
  tag "cci": ['CCI-001764']
  tag "cce": ['CCE-23878-2']
  tag "nist": ['CM-7 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\

  Value Name: NoDriveTypeAutoRun

  Type: REG_DWORD
  Value: 0x000000ff (255)"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> AutoPlay Policies -> \"Turn
  off AutoPlay\" to \"Enabled:All Drives\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoDriveTypeAutoRun' }
    its('NoDriveTypeAutoRun') { should cmp == 255 }
  end
end
