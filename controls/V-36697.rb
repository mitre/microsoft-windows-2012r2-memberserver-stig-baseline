control "V-36697" do
  title "Trusted app installation must be enabled to allow for signed
  enterprise line of business apps."
  desc  "Enabling trusted app installation allows for enterprise line of
  business Windows 8 type apps.   A trusted app package is one that is signed
  with a certificate chain that can be successfully validated in the enterprise.
  Configuring this ensures enterprise line of business apps are accessible."
  impact 0.3
  tag "gtitle": "WINCC-000070"
  tag "gid": "V-36697"
  tag "rid": "SV-51738r1_rule"
  tag "stig_id": "WN12-CC-000070"
  tag "fix_id": "F-44813r1_fix"
  tag "cci": ["CCI-000366"]
  tag "cce": ["CCE-23960-8"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECSC-1"
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Appx\\

  Value Name: AllowAllTrustedApps

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> App Package Deployment  ->
  \"Allow all trusted apps to install\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Appx") do
    it { should have_property "AllowAllTrustedApps" }
    its("AllowAllTrustedApps") { should cmp == 1 }
  end
end

