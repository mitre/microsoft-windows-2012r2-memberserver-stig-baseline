# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-26602' do
  title 'The Microsoft FTP service must not be installed unless required.'
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption."
  impact 0.5
  tag "gtitle": 'Microsoft FTP Service Disabled'
  tag "gid": 'V-26602'
  tag "rid": 'SV-52237r4_rule'
  tag "stig_id": 'WN12-SV-000101'
  tag "fix_id": 'F-74887r1_fix'
  tag "cci": ['CCI-000382']
  tag "cce": ['CCE-23863-4']
  tag "nist": ['CM-7 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the server has the role of an FTP server, this is NA.

  Run \"Services.msc\".

  If the \"Microsoft FTP Service\" (Service name: FTPSVC) is installed and not
  disabled, this is a finding."
  tag "fix": "Remove or disable the \"Microsoft FTP Service\" (Service name:
  FTPSVC).

  To remove the \"FTP Server\" role from a system:
  Start \"Server Manager\"
  Select the server with the \"FTP Server\" role.
  Scroll down to \"ROLES AND FEATURES\" in the left pane.
  Select \"Remove Roles and Features\" from the drop down \"TASKS\" list.
  Select the appropriate server on the \"Server Selection\" page, click \"Next\".
  De-select \"FTP Server\" under \"Web Server (IIS).
  Click \"Next\" and \"Remove\" as prompted."

  is_ftp_installed = command('Get-WindowsFeature Web-Ftp-Server | Select -Expand Installed').stdout.strip

  if is_ftp_installed == 'False'
    describe 'The system does not have Ftp installed' do
      skip 'The system does not have Ftp installed, this requirement is Not Applicable.'
    end
  else
    startmode = powershell('Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq "FTPSVC"} | Select StartMode | ConvertTo-Json').stdout.strip
    clean_startmode = startmode[22..29]
    describe 'Fax Service is installed and disabled' do
      subject { clean_startmode }
      it { should eq 'Disabled' }
    end
  end
end
