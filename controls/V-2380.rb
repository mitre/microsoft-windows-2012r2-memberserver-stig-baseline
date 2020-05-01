# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-2380' do
  title "The computer clock synchronization tolerance must be limited to 5
minutes or less."
  desc  "This setting determines the maximum time difference (in minutes) that
Kerberos will tolerate between the time on a client's clock and the time on a
server's clock while still considering the two clocks synchronous.  In order to
prevent replay attacks, Kerberos uses timestamps as part of its protocol
definition.  For timestamps to work properly, the clocks of the client and the
server need to be in sync as much as possible."
  impact 0.5
  tag 'severity:' 'nil'
  tag 'gtitle:' 'Kerberos - Computer Clock Sync'
  tag 'gid:' 'V-2380'
  tag 'rid:' 'SV-51168r3_rule'
  tag 'stig_id:' 'WN12-AC-000014-DC'
  tag 'fix_id:' 'F-44325r1_fix'
  tag 'cci:' '["CCE-25365-8", "CCI-001941", "CCI-001942"]'
  tag 'nist:' '["IA-2 (8)", "IA-2 (9)", "Rev_4"]'
  tag 'false_negatives:' 'nil'
  tag 'false_positives:' 'nil'
  tag 'documentable:' 'false'
  tag 'mitigations:' 'nil'
  tag 'severity_override_guidance:' 'false'
  tag 'potential_impacts:' 'nil'
  tag 'third_party_tools:' 'nil'
  tag 'mitigation_controls:' 'nil'
  tag 'responsibility:' 'nil'
  tag 'ia_controls:' 'nil'
  tag 'check:' "Verify the following is configured in the Default Domain Policy.

Open \"Group Policy Management\".
Navigate to \"Group Policy Objects\" in the Domain being reviewed (Forest >
Domains > Domain).
Right click on the \"Default Domain Policy\".
Select Edit.
Navigate to Computer Configuration > Policies > Windows Settings > Security
Settings > Account Policies > Kerberos Policy.

If the \"Maximum tolerance for computer clock synchronization\" is greater than
5 minutes, this is a finding."
  tag 'fix:' "Configure the policy value in the Default Domain Policy for
Computer Configuration -> Windows Settings -> Security Settings -> Account
Policies -> Kerberos Policy -> \"Maximum tolerance for computer clock
synchronization\" to a maximum of 5 minutes or less."

  if domain_role == '4' || domain_role == '5'
    describe security_policy do
      its('MaxClockSkew') { should cmp <= 5 }
    end
  else
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
    end
end
