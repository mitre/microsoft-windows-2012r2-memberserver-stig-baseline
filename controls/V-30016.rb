control "V-30016" do
  title "Unauthorized accounts must not have the Add workstations to domain
user right."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    Accounts with the \"Add workstations to domain\" right may add computers to
a domain.  This could result in unapproved or incorrectly configured systems
being added to a domain.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": 'Add workstations to domain'
  tag "gid": 'V-30016'
  tag "rid": 'SV-51143r2_rule'
  tag "stig_id": 'WN12-UR-000044-DC'
  tag "fix_id": "F-44300r2_fix"
  tag "cci": ["CCE-23271-0", "CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls:" 'ECLP-1'
  tag "check:" "Verify the effective setting in Local Group Policy Editor.
Run \"gpedit.msc\".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
-> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the \"Add
workstations to domain\" right, this is a finding:

Administrators"
  tag "fix:" "Configure the policy value for Computer Configuration -> Windows
Settings -> Security Settings -> Local Policies -> User Rights Assignment ->
\"Add workstations to domain\" to only include the following accounts or groups:

Administrators"

end

