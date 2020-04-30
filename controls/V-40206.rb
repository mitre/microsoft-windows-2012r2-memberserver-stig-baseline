control 'V-40206' do
  title 'The Smart Card Removal Policy service must be configured to automatic.'
  desc  "The automatic start of the Smart Card Removal Policy service is
  required to support the smart card removal behavior requirement."
  impact 0.5
  tag "gtitle": 'WNSV-000106'
  tag "gid": 'V-40206'
  tag "rid": 'SV-52165r2_rule'
  tag "stig_id": 'WN12-SV-000106'
  tag "fix_id": 'F-45191r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24365-9']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "Verify the Smart Card Removal Policy service is configured to
  \"Automatic\".

  Run \"Services.msc\".

  If the Startup Type for Smart Card Removal Policy is not set to Automatic, this
  is a finding."
  tag "fix": "Configure the Startup Type for the Smart Card Removal Policy
  service to \"Automatic\"."
  
  is_scpolicysvc_installed = command('Get-Service SCPolicySvc').stdout.strip
  if is_scpolicysvc_installed == ''
    describe 'SCPolicySvc not installed' do
      skip 'This must be checked manually, since the SCPolicySvc is not installed'
    end
  else
    startmode = json( command: 'Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq "SCPolicySvc"} | Select -ExpandProperty StartMode | ConvertTo-Json').params
      describe 'Smart Card Removal Policy is Set to Automatic' do
       subject { startmode}
       it { should eq 'Auto'}
      end
  end
end