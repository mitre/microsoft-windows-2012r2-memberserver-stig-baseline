control "V-3374" do
  title "The system must be configured to require a strong session key."
  desc  "A computer connecting to a domain controller will establish a secure
  channel.  Requiring strong session keys enforces 128-bit encryption between
  systems."
  impact 0.5
  tag "gtitle": "Strong Session Key"
  tag "gid": "V-3374"
  tag "rid": "SV-52888r2_rule"
  tag "stig_id": "WN12-SO-000017"
  tag "fix_id": "F-45814r1_fix"
  tag "cci": ["CCE-25198-3", "CCI-002418", "CCI-002421"]
  tag "nist": ["CCE-25198-3", "CCI-002418", "CCI-002421"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "nist": ["CM-9 c", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

  Value Name: RequireStrongKey

  Value Type: REG_DWORD
  Value: 1

  This setting may prevent a system from being joined to a domain if not
  configured consistently between systems."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"Domain
  member: Require strong (Windows 2000 or Later) session key\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "RequireStrongKey" }
    its("RequireStrongKey") { should cmp == 1 }
  end
end

