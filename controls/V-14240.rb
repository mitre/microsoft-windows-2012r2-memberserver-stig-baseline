# frozen_string_literal: true

control 'V-14240' do
  title "User Account Control must run all administrators in Admin Approval
  Mode, enabling UAC."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting enables UAC."
  impact 0.5
  tag "gtitle": 'UAC - All Admin Approval Mode'
  tag "gid": 'V-14240'
  tag "rid": 'SV-52951r1_rule'
  tag "stig_id": 'WN12-SO-000083'
  tag "fix_id": 'F-45877r2_fix'
  tag "cci": ['CCI-002038']
  tag "cce": ['CCE-23653-9']
  tag "nist": %w[IA-11 Rev_4]
  tag "documentable": false
  tag "check": "UAC requirements are NA on Server Core installations.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: EnableLUA

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "UAC requirements are NA on Server Core installations.

  Configure the policy value for Computer Configuration -> Windows Settings ->
  Security Settings -> Local Policies -> Security Options -> \"User Account
  Control: Run all administrators in Admin Approval Mode\" to \"Enabled\"."

  # command checks to see if install is a Core or Gui Based install, if the result is false it is a server core build, if true it is a full install with gui
  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'false'
    impact 0.0
    describe 'This system is a Server Core Installation, control is NA' do
      skip 'This system is a Server Core Installation control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'EnableLUA' }
      its('EnableLUA') { should cmp == 1 }
    end
  end
end
