control "V-26576" do
  title "The IP-HTTPS IPv6 transition technology must be disabled."
  desc  "IPv6 transition technologies, which tunnel packets through other
  protocols, do not provide visibility."
  impact 0.5
  tag "gtitle": "IP-HTTPS State"
  tag "gid": "V-26576"
  tag "rid": "SV-52969r1_rule"
  tag "stig_id": "WN12-CC-000008"
  tag "fix_id": "F-45895r1_fix"
  tag "cci": ["CCE-25651-1", "CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\IPHTTPS\\IPHTTPSInterface\\

  Value Name: IPHTTPS_ClientState

  Type: REG_DWORD
  Value: 3"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition
  Technologies -> \"Set IP-HTTPS State\" to \"Enabled: Disabled State\".

  Note: \"IPHTTPS URL:\" must be entered in the policy even if set to Disabled
  State.  Enter \"about:blank\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\IPHTTPS\\IPHTTPSInterface") do
    it { should have_property "IPHTTPS_ClientState" }
    its("IPHTTPS_ClientState") { should cmp == 3 }
  end
end

