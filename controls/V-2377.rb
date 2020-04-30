# frozen_string_literal: true

control 'V-2377' do
  title "The Kerberos service ticket maximum lifetime must be limited to 600
minutes or less."
  desc  "This setting determines the maximum amount of time (in minutes) that a
granted session ticket can be used to access a particular service.  Session
tickets are used only to authenticate new connections with servers.  Ongoing
operations are not interrupted if the session ticket used to authenticate the
connection expires during the connection."
  impact 0.5
  tag 'severity:' 'nil'
  tag 'gtitle:''Kerberos-Service Ticket Lifetime'
  tag 'gid:' 'V-2377'
  tag 'rid:' 'SV-51162r2_rule'
  tag 'stig_id:' 'WN12-AC-000011-DC'
  tag 'fix_id:' 'F-44319r1_fix'
  tag 'cci:' '["CCE-23419-5", "CCI-000366"]'
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

If the value for \"Maximum lifetime for service ticket\" is 0 or greater than
600 minutes, this is a finding."
  tag 'fix:' "Configure the policy value in the Default Domain Policy for
Computer Configuration ->  Policies -> Windows Settings -> Security Settings ->
Account Policies -> Kerberos Policy -> \"Maximum lifetime for service ticket\"
to a maximum of 600 minutes, but not 0 which equates to \"Ticket doesn't
expire\"."

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    describe security_policy do
      its('MaxServiceAge') { should eq 600 }
    end
    describe security_policy do
      its('MaxServiceAge') { should_not eq 0 }
    end
  else
    describe 'Server is a Member Server or Standalone, Control V-2377 is NA' do
      skip 'Server is a Member Server or Standalone, Control V-2377 is NA'
    end
 end
end
