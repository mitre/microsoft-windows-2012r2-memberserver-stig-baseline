control "V-16021" do
  title "The Windows Help Experience Improvement Program must be disabled."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting ensures the Windows Help Experience Improvement Program is
  disabled to prevent information from being passed to the vendor.
  "
  impact 0.5
  tag "gtitle": "Help Experience Improvement Program"
  tag "gid": "V-16021"
  tag "rid": "SV-53144r1_rule"
  tag "stig_id": "WN12-UC-000007"
  tag "fix_id": "F-46070r1_fix"
  tag "cci": ["CCI-000381"]
  tag "cce": ["CCE-24925-0"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_CURRENT_USER
  Registry Path: \\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0\\

  Value Name: NoImplicitFeedback

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for User Configuration ->
  Administrative Templates -> System -> Internet Communication Management ->
  Internet Communication Settings -> \"Turn off Help Experience Improvement
  Program\" to \"Enabled\"."
  describe registry_key("HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0") do
    it { should have_property "NoImplicitFeedback" }
    its("NoImplicitFeedback") { should cmp == 1 }
  end
end

