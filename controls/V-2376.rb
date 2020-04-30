# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-2376' do
  title 'Kerberos user logon restrictions must be enforced.'
  desc  "This policy setting determines whether the Kerberos Key Distribution
Center (KDC) validates every request for a session ticket against the user
rights policy of the target computer.  The policy is enabled by default which
is the most secure setting for validating access to target resources is not
circumvented."
  impact 0.5
  tag 'severity:' 'nil'
  tag 'gtitle:' 'Kerberos-User Logon Restrictions'
  tag 'gid:' 'V-2376'
  tag 'rid:' 'SV-51160r2_rule'
  tag 'stig_id:' 'WN12-AC-000010-DC'
  tag 'fix_id:' 'F-44317r1_fix'
  tag 'cci:' '["CCE-23796-6" "CCI-000366"]'
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

If the \"Enforce user logon restrictions\" is not set to \"Enabled\", this is a
finding."
  tag 'fix:' "Configure the policy value in the Default Domain Policy for
Computer Configuration ->  Policies -> Windows Settings -> Security Settings ->
Account Policies -> Kerberos Policy -> \"Enforce user logon restrictions\" to
\"Enabled\"."

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    describe security_policy do
      its('TicketValidateClient') { should eq 1 }
    end
  else
    describe 'Server is a Member Server or Standalone, Control V-2376 is NA' do
      skip 'Server is a Member Server or Standalone, Control V-2376 is NA'
    end
 end
end
