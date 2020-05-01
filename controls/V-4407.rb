# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-4407' do
  title 'Domain controllers must require LDAP access signing.'
  desc  "Unsigned network traffic is susceptible to man in the middle attacks
where an intruder captures packets between the server and the client and
modifies them before forwarding them to the client.  In the case of an LDAP
server, this means that an attacker could cause a client to make decisions
based on false records from the LDAP directory.  You can lower the risk of an
attacker pulling this off in a corporate network by implementing strong
physical security measures to protect the network infrastructure.  Furthermore,
implementing Internet Protocol security (IPSec) authentication header mode
(AH), which performs mutual authentication and packet integrity for Internet
Protocol (IP) traffic, can make all types of man in the middle attacks
extremely difficult."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'LDAP Signing Requirements'
  tag 'gid': 'V-4407'
  tag 'rid': 'SV-51140r3_rule'
  tag 'stig_id': 'WN12-SO-000090-DC'
  tag 'fix_id': 'F-44297r1_fix'
  tag 'cci': ["CCE-23587-9", "CCI-002418", "CCI-002421"]
  tag 'nist': ["SC-8", "SC-8 (1)", "Rev_4"]
  tag 'false_negatives': nil
  tag 'false_positives': nil
  tag 'documentable': false
  tag 'mitigations': nil
  tag 'severity_override_guidance': false
  tag 'potential_impacts': nil
  tag 'third_party_tools': nil
  tag 'mitigation_controls': nil
  tag 'responsibility': nil
  tag 'ia_controls': nil
  tag 'check': "If the following registry value does not exist or is not
configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\

Value Name: LDAPServerIntegrity

Value Type: REG_DWORD
Value: 2"
  tag 'fix': "Configure the policy value for Computer Configuration -> Windows
Settings -> Security Settings -> Local Policies -> Security Options -> \"Domain
controller: LDAP server signing requirements\" to \"Require signing\"."

  if domain_role == '4' || domain_role == '5'
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters') do
      it { should have_property 'LDAPServerIntegrity' }
      its ('LDAPServerIntegrity') { should eq 2 }
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
    end
end
