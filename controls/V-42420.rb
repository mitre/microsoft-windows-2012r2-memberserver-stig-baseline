control "V-42420" do
  title "A host-based firewall must be installed and enabled on the system."
  desc  "A firewall provides a line of defense against attack, allowing or
  blocking inbound and outbound connections based on a set of rules."
  impact 0.5
  tag "gtitle": "WINFW-000001"
  tag "gid": "V-42420"
  tag "rid": "SV-55085r1_rule"
  tag "stig_id": "WN12-FW-000001"
  tag "fix_id": "F-47956r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECSC-1"
  tag "check": "Determine if a host-based firewall is installed and enabled on
  the system.  If a host-based firewall is not installed and enabled on the
  system, this is a finding.

  The configuration requirements will be determined by the applicable firewall
  STIG."
  tag "fix": "Install and enable a host-based firewall on the system."
  describe "A host-based firewall must be installed and enabled on the system" do
    skip "is a manual check"
  end
   describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "EnableFirewall" }
    its("EnableFirewall") { should cmp == 1 }
  end
end

 