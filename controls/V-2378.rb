control "V-2378" do
  title "The Kerberos user ticket lifetime must be limited to 10 hours or less."
  desc  "In Kerberos, there are 2 types of tickets: Ticket Granting Tickets
(TGTs) and Service Tickets.  Kerberos tickets have a limited lifetime so the
time an attacker has to implement an attack is limited.  This policy controls
how long TGTs can be renewed.  With Kerberos, the user's initial authentication
to the domain controller results in a TGT which is then used to request Service
Tickets to resources.  Upon startup, each computer gets a TGT before requesting
a service ticket to the domain controller and any other computers it needs to
access.  For services that startup under a specified user account, users must
always get a TGT first, then get Service Tickets to all computers and services
accessed."
  impact 0.5
  tag "severity:" 'nil'
  tag "gtitle:" 'Kerberos - User Ticket Lifetime'
  tag "gid:" 'V-2378'
  tag "rid:" 'SV-51164r2_rule'
  tag "stig_id:" 'WN12-AC-000012-DC'
  tag "fix_id:" 'F-44321r1_fix'
  tag "cci:" '["CCE-24230-5", "CCI-000366"]'
  tag "nist:" '["CM-6 b", "Rev_4"]'
  tag "false_negatives:" 'nil'
  tag "false_positives:" 'nil'
  tag "documentable:" 'false'
  tag "mitigations:" 'nil'
  tag "severity_override_guidance:" 'false'
  tag "potential_impacts:" 'nil'
  tag "third_party_tools:" 'nil'
  tag "mitigation_controls:" 'nil'
  tag "responsibility:" 'nil'
  tag "ia_controls:" 'ECSC-1'
  tag "check:" "Verify the following is configured in the Default Domain Policy.

Open \"Group Policy Management\".
Navigate to \"Group Policy Objects\" in the Domain being reviewed (Forest >
Domains > Domain).
Right click on the \"Default Domain Policy\".
Select Edit.
Navigate to Computer Configuration > Policies > Windows Settings > Security
Settings > Account Policies > Kerberos Policy.

If the value for \"Maximum lifetime for user ticket\" is 0 or greater than 10
hours, this is a finding."
  tag "fix:" "Configure the policy value in the Default Domain Policy for
Computer Configuration ->  Policies -> Windows Settings -> Security Settings ->
Account Policies -> Kerberos Policy -> \"Maximum lifetime for user ticket\" to
a maximum of 10 hours, but not 0 which equates to \"Ticket doesn't expire\"."

domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

   if domain_role == '4' || domain_role == '5'
    describe security_policy do
     its('MaxTicketAge') { should eq 10 }
    end
    describe security_policy do
     its('MaxTicketAge') { should_not eq 0 }
    end
  else 
    describe 'Server is a Member Server or Standalone, Control V-2378 is NA' do
      skip 'Server is a Member Server or Standalone, Control V-2378 is NA'
    end
  end
end

