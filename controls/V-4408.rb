# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-4408' do
  title "Domain controllers must be configured to allow reset of machine
account passwords."
  desc  "Enabling this setting on all domain controllers in a domain prevents
domain members from changing their computer account passwords.  If these
passwords are weak or compromised, the inability to change them may leave these
computers vulnerable."
  impact 0.3
  tag 'severity:' 'nil'
  tag 'gtitle:' 'Computer Account Password Change'
  tag 'gid:' 'V-4408'
  tag 'rid:' 'SV-51141r2_rule'
  tag 'stig_id:' 'WN12-SO-000091-DC'
  tag 'fix_id:' 'F-44298r1_fix'
  tag 'cci:' '["CCE-24692-6", "CCI-000366"]'
  tag 'nist:' '["CM-6 b", "Rev_4"]'
  tag 'false_negatives:' 'nil'
  tag 'false_positives: ''nil'
  tag 'documentable:' 'false'
  tag 'mitigations:' 'nil'
  tag 'severity_override_guidance:' 'false'
  tag 'potential_impacts:' 'nil'
  tag 'third_party_tools:' 'nil'
  tag 'mitigation_controls:' 'nil'
  tag 'responsibility:' 'nil'
  tag 'ia_controls:' 'ECSC-1'
  tag 'check:' "If the following registry value does not exist or is not
configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RefusePasswordChange

Value Type: REG_DWORD
Value: 0"
  tag 'fix:' "Configure the policy value for Computer Configuration -> Windows
Settings -> Security Settings -> Local Policies -> Security Options -> \"Domain
controller: Refuse machine account password changes\" to \"Disabled\"."

  if domain_role == '4' || domain_role == '5'
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
      it { should have_property 'RefusePasswordChange' }
      its ('RefusePasswordChange') { should eq 0 }
    end
  else
    describe 'Server is a Member Server or Standalone, Control V-4408 is NA' do
      skip 'Server is a Member Server or Standalone, Control V-4408 is NA'
    end
    end
end
