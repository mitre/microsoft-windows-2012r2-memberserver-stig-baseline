# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-15991' do
  title "UIAccess applications must not be allowed to prompt for elevation
  without using the secure desktop."
  desc "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting prevents User Interface Accessibility programs from disabling the
  secure desktop for elevation prompts."
  impact 0.5
  tag "gtitle": 'UAC - UIAccess Secure Desktop'
  tag "gid": 'V-15991'
  tag "rid": 'SV-52223r2_rule'
  tag "stig_id": 'WN12-SO-000086'
  tag "fix_id": 'F-45241r1_fix'
  tag "cci": ['CCI-001084']
  tag "cce": ['CCE-23295-9']
  tag "nist": %w[SC-3 Rev_4]
  tag "documentable": false
  tag "ia_controls": 'ECCD-1, ECCD-2'
  tag "check": "UAC requirements are NA on Server Core installations.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: EnableUIADesktopToggle

  Value Type: REG_DWORD
  Value: 0"
  tag "fix": "UAC requirements are NA on Server Core installations.

  Configure the policy value for Computer Configuration -> Windows Settings ->
  Security Settings -> Local Policies -> Security Options -> \"User Account
  Control: Allow UIAccess applications to prompt for elevation without using the
  secure desktop\" to \"Disabled\"."

  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'false'
    impact 0.0
    describe 'This system is a Server Core Installation, control is NA' do
      skip 'This system is a Server Core Installation control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'EnableUIADesktopToggle' }
      its('EnableUIADesktopToggle') { should cmp == 0 }
    end
  end
end
