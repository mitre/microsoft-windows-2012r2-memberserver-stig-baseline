control "V-36720" do
  title "The Windows Remote Management (WinRM) service must not store RunAs
  credentials."
  desc  "Storage of administrative credentials could allow unauthorized access.
  Disallowing the storage of RunAs credentials for Windows Remote Management
  will prevent them from being used with plug-ins."
  impact 0.5
  tag "gtitle": "WINCC-000128"
  tag "gid": "V-36720"
  tag "rid": "SV-51757r1_rule"
  tag "stig_id": "WN12-CC-000128"
  tag "fix_id": "F-44832r1_fix"
  tag "cci": ["CCI-002038"]
  tag "cce": ["CCE-23262-9"]
  tag "nist": ["IA-11", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECLP-1"
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

  Value Name: DisableRunAs

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Windows Remote Management
  (WinRM) -> WinRM Service -> \"Disallow WinRM from storing RunAs credentials\"
  to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "DisableRunAs" }
    its("DisableRunAs") { should cmp == 1 }
  end
end

