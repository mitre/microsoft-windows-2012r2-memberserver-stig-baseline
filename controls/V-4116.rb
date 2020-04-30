# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-4116' do
  title "The system must be configured to ignore NetBIOS name release requests
  except from WINS servers."
  desc "Configuring the system to ignore name release requests, except from
  WINS servers, prevents a denial of service (DoS) attack.  The DoS consists of
  sending a NetBIOS name release request to the server for each entry in the
  server's cache, causing a response delay in the normal operation of the servers
  WINS resolution capability."
  impact 0.3
  tag "gtitle": 'Name-Release Attacks'
  tag "gid": 'V-4116'
  tag "rid": 'SV-52928r2_rule'
  tag "stig_id": 'WN12-SO-000043'
  tag "fix_id": 'F-45854r3_fix'
  tag "cci": ['CCI-002385']
  tag "cce": ['CCE-23715-6']
  tag "nist": %w[SC-5 Rev_4]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters\\

  Value Name:  NoNameReleaseOnDemand

  Value Type:  REG_DWORD
  Value:  1"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> \"MSS:
  (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release
  requests except from WINS servers\" to \"Enabled\".

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netbt\\Parameters') do
    it { should have_property 'NoNameReleaseOnDemand' }
    its('NoNameReleaseOnDemand') { should cmp == 1 }
  end
end
