# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-80477' do
  title 'Windows PowerShell 2.0 must not be installed on Windows 2012/2012 R2'
  desc "Windows PowerShell versions 4.0 (with a patch) and 5.x add advanced logging features that can provide additional detail when malware has been run on a system.
 Ensuring Windows PowerShell 2.0 is not installed as well mitigates against a downgrade attack that evades the advanced logging features of later
 Windows PowerShell versions."
  impact 0.5
  tag "gtitle": 'WIN00-000220'
  tag "gid": 'V-80477'
  tag "rid": 'SV-95185r1_rule'
  tag "stig_id": 'WN12-00-000220'
  tag "fix_id": '_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7', 'CM-7.1 (ii)', 'Rev_4']
  tag "documentable": false
  tag "check": "Windows PowerShell 2.0 is not installed by default.

Open \"Windows PowerShell\".

Enter \"Get-WindowsFeature -Name PowerShell-v2\".

If \"Installed State\" is \"Installed\", this is a finding.

An Installed State of \"Available\" or \"Removed\" is not a finding."
  tag "fix": "Windows PowerShell 2.0 is not installed by default.

Uninstall it if it has been installed.

Open \"Windows PowerShell\".

Enter \"Uninstall-WindowsFeature -Name PowerShell-v2\".

Alternately:

Use the \"Remove Roles and Features Wizard\" and deselect \"Windows PowerShell 2.0 Engine\" under \"Windows PowerShell\"."

  powershell_v2_installed = powershell('Get-WindowsFeature -Name Powershell-v2 | Select InstallState').stdout.strip
  v2_installed = powershell_v2_installed[31..40]

  describe 'Windows PowerShell 2.0 is not installed by default and should not be installed' do
    subject { v2_installed }
    it { should_not cmp 'Installed' }
  end
end
