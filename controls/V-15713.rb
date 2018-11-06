control "V-15713" do
  title "Microsoft Active Protection Service membership must be disabled."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this feature will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.  This setting
  disables Microsoft Active Protection Service membership and reporting."
  impact 0.5
  tag "gtitle": "Defender – SpyNet Reporting"
  tag "gid": "V-15713"
  tag "rid": "SV-53134r2_rule"
  tag "stig_id": "WN12-CC-000111"
  tag "fix_id": "F-62313r2_fix"
  tag "cci": ["CCI-000381"]
  tag "cce": ["CCE-25247-8"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value exists and is set to \"1\"
  (Basic) or \"2\" (Advanced), this is a finding:

  If the registry value does not exist, this is not a finding.

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\\

  Value Name:  SpyNetReporting

  Type:  REG_DWORD
  Value:  1 or 2 = a Finding"
  tag "fix": "Windows 2012 R2:
  Configure the policy value for Computer Configuration -> Administrative
  Templates -> Windows Components -> Windows Defender -> MAPS -> \"Join Microsoft
  MAPS\" to \"Disabled\".

  Windows 2012:
  Configure the policy value for Computer Configuration -> Administrative
  Templates -> Windows Components -> Windows Defender -> \"Configure Microsoft
  Active Protection Service Reporting\" to \"Disabled\"."
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet") do
      it { should have_property "SpyNetReporting" }
      its("SpyNetReporting") { should cmp != 1 }
    end 

    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet") do
      it { should have_property "SpyNetReporting" }
      its("SpyNetReporting") { should cmp != 2 }
    end
  end 
end

