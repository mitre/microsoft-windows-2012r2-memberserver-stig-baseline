# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-2379' do
  title "The Kerberos policy user ticket renewal maximum lifetime must be
limited to 7 days or less."
  desc  "This setting determines the period of time (in days) during which a
user's TGT may be renewed.  This security configuration limits the amount of
time an attacker has to crack the TGT and gain access."
  impact 0.5
  tag 'severity:' 'nil'
  tag 'gtitle:' 'Kerberos-User Ticket Renewal'
  tag 'gid:' 'V-2379'
  tag 'rid:' 'SV-51166r2_rule'
  tag 'stig_id:' 'WN12-AC-000013-DC'
  tag 'fix_id:' 'F-44324r1_fix'
  tag 'cci:' '["CCE-24125-7", "CCI-000366"]'
  tag 'nist:' '["CM-6 b", "Rev_4"]'
  tag 'false_negatives:' 'nil'
  tag 'false_positives:' 'nil'
  tag 'documentable:' 'false'
  tag 'mitigations:' 'nil'
  tag 'severity_override_guidance:' 'false'
  tag 'potential_impacts:' 'nil'
  tag 'third_party_tools:' 'nil'
  tag 'mitigation_controls:' 'nil'
  tag 'responsibility:' 'nil'
  tag 'ia_controls:' 'ECSC-1'
  tag 'check:' "Verify the following is configured in the Default Domain Policy.

Open \"Group Policy Management\".
Navigate to \"Group Policy Objects\" in the Domain being reviewed (Forest >
Domains > Domain).
Right click on the \"Default Domain Policy\".
Select Edit.
Navigate to Computer Configuration > Policies > Windows Settings > Security
Settings > Account Policies > Kerberos Policy.

If the \"Maximum lifetime for user ticket renewal\" is greater than 7 days,
this is a finding."
  tag 'fix:' "Configure the policy value in the Default Domain Policy for
Computer Configuration ->  Policies -> Windows Settings -> Security Settings ->
Account Policies -> Kerberos Policy -> \"Maximum lifetime for user ticket
renewal\" to a maximum of 7 days or less."

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
    describe security_policy do
      its('MaxRenewAge') { should cmp <= 7 }
    end
  else
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
   end
end
