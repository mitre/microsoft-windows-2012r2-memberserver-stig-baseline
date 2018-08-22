control "V-43241" do
  title "The setting to allow Microsoft accounts to be optional for modern
  style apps must be enabled (Windows 2012 R2)."
  desc  "Control of credentials and the system must be maintained within the
  enterprise.  Enabling this setting allows enterprise credentials to be used
  with modern style apps that support this, instead of Microsoft accounts."
  if (os['release'].to_i < 6.3 )
    impact 0.0
  end
  else
    impact 0.3
  end
  tag "gtitle": "WINCC-000141"
  tag "gid": "V-43241"
  tag "rid": "SV-56353r2_rule"
  tag "stig_id": "WN12-CC-000141"
  tag "fix_id": "F-49195r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "This requirement is NA for the initial release of Windows 2012.
   It is applicable to Windows 2012 R2.

  Verify the registry value below.  If it does not exist or is not configured as
  specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System

  Value Name: MSAOptional

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "This requirement is NA for the initial release of Windows 2012.
  It is applicable to Windows 2012 R2.

  Configure the policy value for Computer Configuration -> Administrative
  Templates -> Windows Components -> App Runtime -> \"Allow Microsoft accounts to
  be optional\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "MSAOptional" }
    its("MSAOptional") { should cmp == 1 }
  end
  only_if do
    os['release'].to_i >= 6.3
  end
end

