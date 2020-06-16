# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-43245' do
  title "Automatically signing in the last interactive user after a
  system-initiated restart must be disabled (Windows 2012 R2)."
  desc "Windows 2012 R2 can be configured to automatically sign the user back
  in after a Windows Update restart.  Some protections are in place to help
  ensure this is done in a secure fashion; however, disabling this will prevent
  the caching of credentials for this purpose and also ensure the user is aware
  of the restart."
  impact 0.5
  tag "gtitle": 'WINCC-000145'
  tag "gid": 'V-43245'
  tag "rid": 'SV-56355r2_rule'
  tag "stig_id": 'WN12-CC-000145'
  tag "fix_id": 'F-49196r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "This requirement is NA for the initial release of Windows 2012.
  It is applicable to Windows 2012 R2.

  Verify the registry value below.  If it does not exist or is not configured as
  specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: DisableAutomaticRestartSignOn

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "This requirement is NA for the initial release of Windows 2012.
  It is applicable to Windows 2012 R2.

  Configure the policy value for Computer Configuration -> Administrative
  Templates -> Windows Components -> Windows Logon Options -> \"Sign-in last
  interactive user automatically after a system-initiated restart\" to
  \"Disabled\"."

  if os['release'].to_f < 6.3
    impact 0.0
    describe 'System is not Windows 2012, control is NA' do
      skip 'System is not Windows 2012, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'DisableAutomaticRestartSignOn' }
      its('DisableAutomaticRestartSignOn') { should cmp == 1 }
    end
  end
end
