control "V-26600" do
  title "The Fax service must be disabled if installed."
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption."
  impact 0.5
  tag "gtitle": "Fax Service Disabled "
  tag "gid": "V-26600"
  tag "rid": "SV-52236r2_rule"
  tag "stig_id": "WN12-SV-000100"
  tag "fix_id": "F-45251r1_fix"
  tag "cci": ["CCE-25383-1", "CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECSC-1"
  tag "check": "Verify the Fax (fax) service is not installed or is disabled.

  Run \"Services.msc\".

  If the following is installed and not disabled, this is a finding:

  Fax (fax)"
  tag "fix": "Remove or disable the Fax (fax) service."

  is_fax_installed = command("Get-WindowsFeature Fax | Select -Expand Installed").stdout.strip
  if (is_fax_installed == 'False' || is_fax_installed == '')
    describe 'Fax not installed' do
      skip "control NA, Fax is not installed"
    end
  else
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT startmode FROM Win32_Service WHERE name='Fax'"}).params.values do
      its("join") { should eq "Disabled" }
    end
  end
end

