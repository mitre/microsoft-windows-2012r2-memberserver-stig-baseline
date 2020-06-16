control "V-39334" do
  title "Domain controllers must have a PKI server certificate."
  desc  "Domain controller must have a server certificate to establish
authenticity as part of PKI authentications in the domain."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'WINPK-000005-DC'
  tag 'gid': 'V-39334'
  tag 'rid': 'SV-51189r2_rule'
  tag 'stig_id': 'WN12-PK-000005-DC'
  tag 'fix_id': 'F-44346r2_fix'
  tag 'cci': ["CCI-000185"]
  tag 'nist': ["IA-5 (2) (a)", "Rev_4"]
  tag 'false_negatives': nil
  tag 'false_positives': nil
  tag 'documentable': false
  tag 'mitigations': nil
  tag 'severity_override_guidance': false
  tag 'potential_impacts': nil
  tag 'third_party_tools': nil
  tag 'mitigation_controls': nil
  tag 'responsibility': nil
  tag 'ia_controls': "IATS-1, IATS-2"
  tag 'check': "Verify the domain controller has a PKI server certificate.

Run \"mmc\".
Select \"Add/Remove Snap-in\" from the File menu.
Select \"Certificates\" in the left pane and click the \"Add >\" button.
Select \"Computer Account\", click \"Next\".
Select the appropriate option for \"Select the computer you want this snap-in
to manage.\", click \"Finish\".
Click \"OK\".
Select and expand the Certificates (Local Computer) entry in the left pane.
Select and expand the Personal entry in the left pane.
Select the Certificates entry in the left pane.

If no certificate for the domain controller exists in the right pane, this is a
finding."
  tag 'fix': "Obtain a server certificate for the domain controller."

      query = json({ command: 'Get-ChildItem -Path Cert:Localmachine\\\\My | Select Subject | ConvertTo-Json' }).params

      domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
       if domain_role == '4' || domain_role == '5'
        if query.empty?
        describe 'Certificates' do
          subject { query }
          it 'should not be empty, ' do
          failure_message = "this is a finding"
          expect(query).not_to be_empty, failure_message
          end
        end
      elsif 
        describe 'There are Certificates in the Personal Store of Domain Controller' do
          skip 'There are Certificates in the Personal Store of Domain Controller'
        end
       end
    else
      impact 0.0
      desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
      describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
       skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
     end
    end
end

