control 'V-26600' do
  title 'The Fax service must be disabled if installed.'
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption."
  impact 0.5
  tag "gtitle": 'Fax Service Disabled'
  tag "gid": 'V-26600'
  tag "rid": 'SV-52236r2_rule'
  tag "stig_id": 'WN12-SV-000100'
  tag "fix_id": 'F-45251r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-25383-1']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "Verify the Fax (fax) service is not installed or is disabled.

  Run \"Services.msc\".

  If the following is installed and not disabled, this is a finding:

  Fax (fax)"
  tag "fix": 'Remove or disable the Fax (fax) service.'
  
  is_fax_installed = command('Get-WindowsFeature Fax | Select -Expand Installed').stdout.strip

  if is_fax_installed == 'False'
    impact 0.0
    describe 'The system does not have Fax installed' do
      skip 'The system does not have Fax installed, this requirement is Not Applicable.'
    end
  else
    startmode = powershell('Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq "fax"} | Select StartMode | ConvertTo-Json').stdout.strip
    clean_startmode = startmode[22..29]
    describe 'Fax Service is installed and disabled' do
      subject { clean_startmode }
      it { should eq 'Disabled'}
    end
  end
end
