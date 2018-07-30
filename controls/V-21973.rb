control "V-21973" do
  title "Autoplay must be turned off for non-volume devices."
  desc  "Allowing Autoplay to execute may introduce malicious code to a system.
  Autoplay begins reading from a drive as soon as media is inserted into the
  drive.  As a result, the setup file of programs or music on audio media may
  start.  This setting will disable Autoplay for non-volume devices (such as
  Media Transfer Protocol (MTP) devices)."
  impact 0.7
  tag "gtitle": "Autoplay for non-volume devices"
  tag "gid": "V-21973"
  tag "rid": "SV-53126r2_rule"
  tag "stig_id": "WN12-CC-000072"
  tag "fix_id": "F-46052r1_fix"
  tag "cci": ["CCE-24715-5", "CCI-001764"]
  tag "nist": ["CCE-24715-5", "CCI-001764"]
  tag "nist": ["CM-7 (2)", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

  Value Name: NoAutoplayfornonVolume

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> AutoPlay Policies ->
  \"Disallow Autoplay for non-volume devices\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    it { should have_property "NoAutoplayfornonVolume" }
    its("NoAutoplayfornonVolume") { should cmp == 1 }
  end
end

