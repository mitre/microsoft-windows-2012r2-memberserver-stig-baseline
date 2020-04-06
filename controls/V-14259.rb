control 'V-14259' do
  title 'Printing over HTTP must be prevented.'
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting prevents the client computer from printing over HTTP, which
  allows the computer to print to printers on the intranet as well as the
  Internet.
  "
  impact 0.5
  tag "gtitle": 'Printing Over HTTP'
  tag "gid": 'V-14259'
  tag "rid": 'SV-52997r1_rule'
  tag "stig_id": 'WN12-CC-000039'
  tag "fix_id": 'F-45924r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24832-8']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Printers\\

  Value Name: DisableHTTPPrinting

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Internet Communication Management ->
  Internet Communication settings -> \"Turn off printing over HTTP\" to
  \"Enabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should have_property 'DisableHTTPPrinting' }
    its('DisableHTTPPrinting') { should cmp == 1 }
  end
end
