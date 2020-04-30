control "V-8322" do
  title "Time synchronization must be enabled on the domain controller."
  desc  "When a directory service using multi-master replication (such as AD)
executes on computers that do not have synchronized time, directory data may be
corrupted or updated invalidly.

    The lack of synchronized time could lead to audit log data that is
misleading, inconclusive, or unusable. In cases of intrusion this may
invalidate the audit data as a source of forensic evidence in an incident
investigation.

    In AD, the lack of synchronized time could prevent clients from logging on
or accessing server resources as a result of Kerberos requirements related to
time variance.
  "
  impact 0.5
  tag "severity": 'nil'
  tag "gtitle": 'Time Synchronization'
  tag "gid": 'V-8322'
  tag "rid": 'SV-51181r2_rule'
  tag "stig_id": 'WN12-AD-000007-DC'
  tag "fix_id": 'F-44338r1_fix'
  tag "cci": ["CCI-001891"]
  tag "nist": ["AU-8 (1) (a)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": 'ECTM-1, ECTM-2'
  tag "check:" "Determine if a time synchronization tool has been implemented on
the Windows domain controller.

If  the Windows Time Service is used, verify the following registry values.  If
they are not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE

Registry Path:
\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient\\
Value Name: Enabled
Type: REG_DWORD
Value: 1

Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\Parameters\\
Value Name: Type
Type: REG_SZ
Value: NT5DS (preferred), NTP or Allsync

If these Windows checks indicate a finding because the NtpClient is not
enabled, determine if an alternate time synchronization tool is installed and
enabled.

If the Windows Time Service is not enabled and no alternate tool is enabled,
this is a finding."
  tag "fix:" "Ensure the Windows Time Service is configured as follows or install
and enable another time synchronization tool.

Registry Hive: HKEY_LOCAL_MACHINE

Registry Path:
\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient\\
Value Name: Enabled
Type: REG_DWORD
Value: 1

Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\ Parameters\\
Value Name: Type
Type: REG_SZ
Value: NT5DS (preferred), NTP or Allsync"

domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
 if domain_role == '4' || domain_role == '5'
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient") do
    it { should have_property 'Enabled' }
    its ('Enabled') { should cmp 1 }
  end
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\Parameters") do
      it { should have_property 'Type' }
      its('Type') { should cmp 'NT5DS' }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\Parameters") do
      it { should have_property 'Type' }
      its('Type') { should cmp 'NTP' }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\Parameters") do
      it { should have_property 'Type' }
      its('Type') { should cmp 'Allsync' }
    end
  end 
 else
   describe 'Server is a Member Server or Standalone, Control V-8322 is NA' do
      skip 'Server is a Member Server or Standalone, Control V-8322 is NA'
   end
 end
end

