# frozen_string_literal: true

control 'V-16008' do
  title "Windows must elevate all applications in User Account Control, not
  just signed ones."
  desc "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting configures whether Windows elevates all applications, or only
  signed ones."
  impact 0.5
  tag "gtitle": 'UAC - Application Elevations'
  tag "gid": 'V-16008'
  tag "rid": 'SV-53142r1_rule'
  tag "stig_id": 'WN12-SO-000081'
  tag "fix_id": 'F-46068r2_fix'
  tag "cci": ['CCI-001084']
  tag "cce": ['CCE-23880-8']
  tag "nist": %w[SC-3 Rev_4]
  tag "documentable": false
  tag "check": "UAC requirements are NA on Server Core installations.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: ValidateAdminCodeSignatures

  Value Type: REG_DWORD
  Value: 0"
  tag "fix": "UAC requirements are NA on Server Core installations.

  Configure the policy value for Computer Configuration -> Windows Settings ->
  Security Settings -> Local Policies -> Security Options -> \"User Account
  Control: Only elevate executables that are signed and validated\" to
  \"Disabled\"."

  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'false'
    impact 0.0
    describe 'This system is a Server Core Installation, control is NA' do
      skip 'This system is a Server Core Installation, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'ValidateAdminCodeSignatures' }
      its('ValidateAdminCodeSignatures') { should cmp == 0 }
    end
  end
end
