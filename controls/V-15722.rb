control "V-15722" do
  title "Windows Media Digital Rights Management (DRM) must be prevented from
  accessing the Internet."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This check verifies that Windows Media DRM will be prevented from accessing
  the Internet.
  "
  impact 0.5
  tag "gtitle": "Media DRM – Internet Access"
  tag "gid": "V-15722"
  tag "rid": "SV-53139r1_rule"
  tag "stig_id": "WN12-CC-000120"
  tag "fix_id": "F-46065r1_fix"
  tag "cci": ["CCE-24380-8", "CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\WMDRM\\

  Value Name: DisableOnline

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Windows Media Digital Rights
  Management -> \"Prevent Windows Media DRM Internet Access\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WMDRM") do
    it { should have_property "DisableOnline" }
    its("DisableOnline") { should cmp == 1 }
  end
end

