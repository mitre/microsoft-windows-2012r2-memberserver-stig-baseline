control "V-15674" do
  title "The Internet File Association service must be turned off."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting prevents unhandled file associations from using the Microsoft
  Web service to find an application.
  "
  impact 0.5
  tag "gtitle": "Internet File Association Service "
  tag "gid": "V-15674"
  tag "rid": "SV-53021r1_rule"
  tag "stig_id": "WN12-CC-000038"
  tag "fix_id": "F-45947r1_fix"
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24899-7']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

  Value Name: NoInternetOpenWith

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Internet Communication Management ->
  Internet Communication settings -> \"Turn off Internet File Association
  service\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoInternetOpenWith' }
    its('NoInternetOpenWith') { should cmp == 1 }
  end
end

