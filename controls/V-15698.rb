control "V-15698" do
  title "The configuration of wireless devices using Windows Connect Now must
  be disabled."
  desc  "Windows Connect Now allows the discovery and configuration of devices
  over wireless.  Wireless devices must be managed.  If a rogue device is
  connected to a system, there is potential for sensitive information to be
  compromised."
  impact 0.5
  tag "gtitle": "Network – WCN Wireless Configuration "
  tag "gid": "V-15698"
  tag "rid": "SV-53085r1_rule"
  tag "stig_id": "WN12-CC-000012"
  tag "fix_id": "F-46011r1_fix"
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-23804-8']
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
  tag "check": "If the following registry values do not exist or are not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars\\

  Value Name: DisableFlashConfigRegistrar
  Value Name: DisableInBand802DOT11Registrar
  Value Name: DisableUPnPRegistrar
  Value Name: DisableWPDRegistrar
  Value Name: EnableRegistrars

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> Windows Connect Now -> \"Configuration
  of wireless settings using Windows Connect Now\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'DisableInBand802DOT11Registrar' }
    its('DisableInBand802DOT11Registrar') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'DisableFlashConfigRegistrar' }
    its('DisableFlashConfigRegistrar') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'DisableUPnPRegistrar' }
    its('DisableUPnPRegistrar') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'DisableWPDRegistrar' }
    its('DisableWPDRegistrar') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'EnableRegistrars' }
    its('EnableRegistrars') { should cmp == 0 }
  end
end

