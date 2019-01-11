control "V-36707" do
  title "Windows SmartScreen must be enabled on Windows 2012/2012 R2."
  desc  "Windows SmartScreen helps protect systems from programs downloaded
  from the Internet that may be malicious. Warning a user before running
  downloaded unknown software, at minimum, will help prevent potentially
  malicious programs from executing."
  impact 0.5
  tag "gtitle": "WINCC-000088"
  tag "gid": "V-36707"
  tag "rid": "SV-51747r4_rule"
  tag "stig_id": "WN12-CC-000088"
  tag "fix_id": "F-87297r2_fix"
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-23531-7']
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
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

  Value Name: EnableSmartScreen

  Type: REG_DWORD
  Value:  0x00000001 (1) (Give user a warning…)
  Or 0x00000002 (2) (Require approval…)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> File Explorer >> \"Configure
  Windows SmartScreen\" to \"Enabled\" with either \"Give user a warning before
  running downloaded unknown software\" or \"Require approval from an
  administrator before running downloaded unknown software\" selected.

  Microsoft has changed this setting several times in the Windows 10
  administrative templates, which will affect group policies in a domain if later
  templates are used.

  v1607 of Windows 10 and Windows Server 2016 changed the setting to only Enabled
  or Disabled without additional selections.  Enabled is effectively \"Give user
  a warning…\".

  v1703 of Windows 10 or later administrative templates changed the policy name
  to \"Configure Windows Defender SmartScreen\", and the selectable options are
  \"Warn\" and \"Warn and prevent bypass\". When either of these are applied to a
  Windows 2012/2012 R2 system, it will configure the registry equivalent of
  \"Give user a warning…\")."
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
      it { should have_property 'EnableSmartScreen' }
      its('EnableSmartScreen') { should cmp == 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
      it { should have_property 'EnableSmartScreen' }
      its('EnableSmartScreen') { should cmp == 2 }
    end
  end
end

