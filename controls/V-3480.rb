# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-3480' do
  title "Windows Media Player must be configured to prevent automatic checking
  for updates."
  desc "Uncontrolled system updates can introduce issues to a system.  The
  automatic check for updates performed by Windows Media Player must be disabled
  to ensure a constant platform and to prevent the introduction of
  unknown\\untested software on the system."
  impact 0.5
  tag "gtitle": 'Media Player - Disable Automatic Updates'
  tag "gid": 'V-3480'
  tag "rid": 'SV-53130r1_rule'
  tag "stig_id": 'WN12-CC-000122'
  tag "fix_id": 'F-46056r1_fix'
  tag "cci": ['CCI-001812']
  tag "cce": ['CCE-24250-3']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "Windows Media Player is not installed by default.  If it is not
  installed, this is NA.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

  Value Name: DisableAutoupdate

  Type: REG_DWORD
  Value: 1"
  tag "fix": "If Windows Media Player is installed, configure the policy value
  for Computer Configuration -> Administrative Templates -> Windows Components ->
  Windows Media Player -> \"Prevent Automatic Updates\" to \"Enabled\"."

  if registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer').exists?
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsMediaPlayer') do
      it { should have_property 'DisableAutoUpdate' }
      its('DisableAutoUpdate') { should cmp == 1 }
    end
  end

  unless registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer').exists?
    impact 0.0
    describe 'The system does not have Windows WindowsMediaPlayer installed' do
      skip "The system does not have Windows WindowsMediaPlayer installed, this requirement is Not
      Applicable."
    end
  end
end
