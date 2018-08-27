is_simptcp_installed = command("Get-Service simptcp").stdout.strip
control "V-26605" do
  title "The Simple TCP/IP Services service must be disabled if installed."
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption."
  if is_simptcp_installed == 'False' || is_simptcp_installed == ''
    impact 0.0
  else
    impact 0.5
  end
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
  describe wmi({
  class: 'win32_service',
  filter: "name like '%simptcp%'"
  }) do
    its('StartMode') { should cmp 'Disabled' }
  end if is_simptcp_installed == 'True'

  describe "The system does not have simptcp installed" do
    skip "The system does not have simptcp installed, this requirement is Not Applicable."
  end if is_simptcp_installed == 'False' || is_simptcp_installed == ''
end
