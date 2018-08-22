control "V-36710" do
  title "Automatic download of updates from the Windows Store must be turned
  off."
  desc  "Uncontrolled system updates can introduce issues to a system.
  Obtaining update components from an outside source may also potentially allow
  sensitive information outside of the enterprise.  Application updates must be
  obtained from an internal source."
  if registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore').exists?
    impact 0.3
  else
    impact 0.0
  end
  tag "gtitle": "WINCC-000109"
  tag "gid": "V-36710"
  tag "rid": "SV-51750r2_rule"
  tag "stig_id": "WN12-CC-000109"
  tag "fix_id": "F-62329r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "The Windows Store is not installed by default.  If the
  \\Windows\\WinStore directory does not exist, this is NA.
  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Windows 2012 R2:
  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsStore\\

  Value Name:  AutoDownload

  Type:  REG_DWORD
  Value:  0x00000002 (2)

  Windows 2012:
  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsStore\\WindowsUpdate\\

  Value Name:  AutoDownload

  Type:  REG_DWORD
  Value:  0x00000002 (2)"
  tag "fix": "The Windows Store is not installed by default.  If the
  \\Windows\\WinStore directory does not exist, this is NA.

  Windows 2012 R2:
  Windows 2012 R2 split the original policy that configures this setting into two
  separate ones.  Configuring either one to \"Enabled\" will update the registry
  value as identified in the Check section.

  Configure the policy value for Computer Configuration -> Administrative
  Templates -> Windows Components -> Store ->
  \"Turn off Automatic Download of updates on Win8 machines\" or \"Turn off
  Automatic Download and install of updates\" to \"Enabled\".

  Windows 2012:
  Configure the policy value for Computer Configuration -> Administrative
  Templates -> Windows Components -> Store -> \"Turn off Automatic Download of
  updates\" to \"Enabled\"."

  if (os['release'].to_i >= 6.3 )
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore") do
      it { should have_property "AutoDownload" }
      its("AutoDownload") { should cmp == 2 }
    end if registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore').exists?
  end

  if (os['release'].to_i < 6.3 )
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore\\WindowsUpdate") do
      it { should have_property "AutoDownload" }
      its("AutoDownload") { should cmp == 2 }
    end if registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore').exists?
  end
  
  describe "The system does not have Windows Store installed" do
    skip "The system does not have Windows Store installed, this requirement is Not
    Applicable."
  end if !registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore').exists?
end

