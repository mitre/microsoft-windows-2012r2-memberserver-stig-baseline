control "V-36439" do
  title "Local administrator accounts must have their privileged token filtered
  to prevent elevated privileges from being used over the network on domain
  systems."
  desc  "A compromised local administrator account can provide means for an
  attacker to move laterally between domain systems.

  With User Account Control enabled, filtering the privileged token for local
  administrator accounts will prevent the elevated privileges of these accounts
  from being used over the network.
  "
  impact 0.5
  tag "gtitle": "Local admin accounts filtered token policy enabled on domain
  systems."
  tag "gid": "V-36439"
  tag "rid": "SV-51590r3_rule"
  tag "stig_id": "WN12-RG-000003-MS"
  tag "fix_id": "F-81023r1_fix"
  tag "cci": ["CCI-001084"]
  tag "nist": ["SC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "If the system is not a member of a domain, this is NA.
  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: LocalAccountTokenFilterPolicy

  Type: REG_DWORD
  Value: 0x00000000 (0)

  This setting may cause issues with some network scanning tools if local
  administrative accounts are used remotely. Scans should use domain accounts
  where possible. If a local administrative account must be used, temporarily
  enabling the privileged token by configuring the registry value to 1 may be
  required."
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> MS Security Guide >> \"Apply UAC restrictions to
  local accounts on network logons\" to \"Enabled\".

  This policy setting requires the installation of the SecGuide custom templates
  included with the STIG package. \"SecGuide.admx\" and \"SecGuide.adml\" must be
  copied to the \\Windows\\PolicyDefinitions and
  \\Windows\\PolicyDefinitions\\en-US directories respectively."
  is_domain = command("wmic computersystem get domain1 | FINDSTR /V Domain").stdout.strip

  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "LocalAccountTokenFilterPolicy" }
    its("LocalAccountTokenFilterPolicy") { should cmp == 0 }
  end
  only_if {is_domain != " "}
end

