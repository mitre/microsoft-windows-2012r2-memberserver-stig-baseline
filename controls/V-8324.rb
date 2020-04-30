# frozen_string_literal: true

control 'V-8324' do
  title "The time synchronization tool must be configured to enable logging of
time source switching."
  desc  "When a time synchronization tool executes, it may switch between time
sources according to network or server contention.  If switches between time
sources are not logged, it may be difficult or impossible to detect malicious
activity or availability problems."
  impact 0.3
  tag "severity": nil
  tag "gtitle": 'Time Synchronization Source Logging'
  tag "gid": 'V-8324'
  tag "rid": 'SV-51182r3_rule'
  tag "stig_id": 'WN12-AD-000008-DC'
  tag "fix_id": 'F-47824r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag 'ia_controls:' 'ECTM-1, ECTM-2'
  tag 'check:' "Verify logging is configured to capture time source switches.

If the Windows Time Service is used, verify the following registry value.  If
it is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\Config\\

Value Name: EventLogFlags

Type: REG_DWORD
Value: 2 or 3

If another time synchronization tool is used, review the available
configuration options and logs.  If the tool has time source logging capability
and it is not enabled, this is a finding."
  tag 'fix:' "Configure the time synchronization tool to log time source
switching.  If the Windows Time Service is used, configure the following
registry value.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\Config\\

Value Name: EventLogFlags

Type: REG_DWORD
Value: 2 or 3"

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\Config') do
        it { should have_property 'EventLogFlags' }
        its('EventLogFlags') { should cmp 2 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\Config') do
        it { should have_property 'EventLogFlags' }
        its('EventLogFlags') { should cmp 3 }
      end
    end
  else
    describe 'Server is a Member Server or Standalone, Control V-8324 is NA' do
      skip 'Server is a Member Server or Standalone, Control V-8324 is NA'
    end
  end
end
