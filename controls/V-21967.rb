control "V-21967" do
  title "Microsoft Support Diagnostic Tool (MSDT) interactive communication
  with Microsoft must be prevented."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting prevents the MSDT from communicating with and sending
  collected data to Microsoft, the default support provider.
  "
  impact 0.3
  tag "gtitle": "MSDT Interactive Communication"
  tag "gid": "V-21967"
  tag "rid": "SV-53187r1_rule"
  tag "stig_id": "WN12-CC-000066"
  tag "fix_id": "F-46113r2_fix"
  tag "cci": ["CCE-23633-1", "CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy\\

  Value Name: DisableQueryRemoteServer

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Troubleshooting and Diagnostics ->
  Microsoft Support Diagnostic Tool -> \"Microsoft Support Diagnostic Tool: Turn
  on MSDT interactive communication with support provider\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy") do
    it { should have_property "DisableQueryRemoteServer" }
    its("DisableQueryRemoteServer") { should cmp == 0 }
  end
end

