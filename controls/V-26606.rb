# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-26606' do
  title 'The Telnet service must be disabled if installed.'
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption."
  impact 0.5
  tag "gtitle": 'Telnet Service Disabled'
  tag "gid": 'V-26606'
  tag "rid": 'SV-52240r2_rule'
  tag "stig_id": 'WN12-SV-000105'
  tag "fix_id": 'F-45255r1_fix'
  tag "cci": ['CCI-000382']
  tag "cci": ['CCE-24474-9']
  tag "nist": ['CM-7 b', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "Verify the Telnet (tlntsvr) service is not installed or is
  disabled.

  Run \"Services.msc\".

  If the following is installed and not disabled, this is a finding:

  Telnet (tlntsvr)"
  tag "fix": 'Remove or disable the Telnet (tlntsvr) service.'

  is_telnetserver_installed = command('Get-WindowsFeature telnet-server | Select -Expand Installed').stdout.strip

  startmode = powershell('Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq "tlntsvr"} | Select StartMode | ConvertTo-Json').stdout.strip
  clean_startmode = startmode[22..29]

  if is_telnetserver_installed == 'False'
    describe 'The system does not have Telnet Server installed' do
      skip 'The system does not have Telnet Server installed, this requirement is Not Applicable.'
    end
  else
    describe 'Telnet Service is installed and disabled' do
      subject { clean_startmode }
      it { should eq 'Disabled' }
    end
  end
end
