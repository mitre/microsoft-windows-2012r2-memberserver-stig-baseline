is_tlntsvr_installed = command("Get-Service tlntsvr").stdout.strip
control "V-26606" do
  title "The Telnet service must be disabled if installed."
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption."
  if is_tlntsvr_installed == 'False' || is_tlntsvr_installed == ''
    impact 0.0
  else
    impact 0.5
  end
  tag "gtitle": "Telnet Service Disabled"
  tag "gid": "V-26606"
  tag "rid": "SV-52240r2_rule"
  tag "stig_id": "WN12-SV-000105"
  tag "fix_id": "F-45255r1_fix"
  tag "cci": ["CCE-24474-9", "CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECSC-1"
  tag "check": "Verify the Telnet (tlntsvr) service is not installed or is
  disabled.

  Run \"Services.msc\".

  If the following is installed and not disabled, this is a finding:

  Telnet (tlntsvr)"
  tag "fix": "Remove or disable the Telnet (tlntsvr) service."
  describe wmi({
  class: 'win32_service',
  filter: "name like '%tlntsvr%'"
  }) do
    its('StartMode') { should cmp 'Disabled' }
  end if is_tlntsvr_installed == 'True'

  describe "The system does not have tlntsvr installed" do
    skip "The system does not have tlntsvr installed, this requirement is Not Applicable."
  end if is_tlntsvr_installed == 'False' || is_tlntsvr_installed == ''
end

