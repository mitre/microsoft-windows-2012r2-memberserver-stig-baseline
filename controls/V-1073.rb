control "V-1073" do
  title "Systems must be maintained at a supported service pack level."
  desc  "Systems at unsupported service packs or releases will not receive
  security updates for new vulnerabilities, which leave them subject to
  exploitation.  Systems must be maintained at a service pack level supported by
  the vendor with new security updates."
  impact 0.7
  tag "gtitle": "Unsupported Service Packs"
  tag "gid": "V-1073"
  tag "rid": "SV-53189r2_rule"
  tag "stig_id": "WN12-GE-000001"
  tag "fix_id": "F-46115r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "Run \"winver.exe\".

  If the \"About Windows\" dialog box does not display
  \"Microsoft Windows Server
  Version 6.2 (Build 9200)\"
  or greater, this is a finding.

  No preview versions will be used in a production environment.

  Unsupported Service Packs/Releases:
  Windows 2012 - any release candidates or versions prior to the initial release."
  tag "fix": "Update the system to a supported release or service pack level."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion") do
    it { should have_property "CurrentVersion" }
    its("CurrentVersion") { should cmp >= '6.2' }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion") do
    it { should have_property "CurrentBuildNumber" }
    its("CurrentBuildNumber") { should cmp >= '9200' }
  end
end

