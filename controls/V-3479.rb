control "V-3479" do
  title "The system must be configured to use Safe DLL Search Mode."
  desc  "The default search behavior, when an application calls a function in a
  Dynamic Link Library (DLL), is to search the current directory, followed by the
  directories contained in the system's path environment variable.  An
  unauthorized DLL, inserted into an application's working directory, could allow
  malicious code to be run on the system.  Setting this policy value forces the
  system to search the %Systemroot% for the DLL before searching the current
  directory or the rest of the path."
  impact 0.5
  tag "gtitle": "Safe DLL Search Mode"
  tag "gid": "V-3479"
  tag "rid": "SV-52920r1_rule"
  tag "stig_id": "WN12-SO-000045"
  tag "fix_id": "F-45846r2_fix"
  tag "cci": ["CCE-23462-5", "CCI-000366"]
  tag "nist": ["CCE-23462-5", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\

  Value Name: SafeDllSearchMode

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"MSS:
  (SafeDllSearchMode) Enable Safe DLL search mode (recommended)\" to \"Enabled\".

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager") do
    it { should have_property "SafeDllSearchMode" }
    its("SafeDllSearchMode") { should cmp == 1 }
  end
end

