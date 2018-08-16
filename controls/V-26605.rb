control "V-26605" do
  title "The Simple TCP/IP Services service must be disabled if installed."
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption."
  impact 0.5
  tag "gtitle": "Simple TCP/IP Services Disabled"
  tag "gid": "V-26605"
  tag "rid": "SV-52239r2_rule"
  tag "stig_id": "WN12-SV-000104"
  tag "fix_id": "F-45254r1_fix"
  tag "cci": ["CCE-23748-7", "CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECSC-1"
  tag "check": "Verify the Simple TCP/IP (simptcp) service is not installed or
  is disabled.

  Run \"Services.msc\".

  If the following is installed and not disabled, this is a finding:

  Simple TCP/IP Services (simptcp)"
  tag "fix": "Remove or disable the Simple TCP/IP Services (simptcp) service."
  is_simptcp_installed = command("Get-Service simptcp").stdout.strip
  if (is_simptcp_installed == '')
    describe 'simptcp not installed' do
      skip "control NA, simptcp is not installed"
    end
  else
    describe wmi({:namespace=>"root\\cimv2", :query=>"SELECT startmode FROM Win32_Service WHERE name='simptcp'"}).params.values do
      its("join") { should eq "Disabled" }
    end
  end
end
