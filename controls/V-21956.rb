# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-21956' do
  title "IPv6 TCP data retransmissions must be configured to prevent resources
  from becoming exhausted."
  desc "Configuring Windows to limit the number of times that IPv6 TCP
  retransmits unacknowledged data segments before aborting the attempt helps
  prevent resources from becoming exhausted."
  impact 0.3
  tag "gtitle": 'IPv6 TCP Data Retransmissions'
  tag "gid": 'V-21956'
  tag "rid": 'SV-53181r2_rule'
  tag "stig_id": 'WN12-SO-000047'
  tag "fix_id": 'F-46107r2_fix'
  tag "cci": ['CCI-002385']
  tag "cce": ['CCE-25202-3']
  tag "nist": %w[SC-5 Rev_4]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\

  Value Name:  TcpMaxDataRetransmissions

  Value Type:  REG_DWORD
  Value:  3 (or less)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> \"MSS:
  (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is
  retransmitted (3 recommended, 5 is default)\" to \"3\" or less.

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters') do
    it { should have_property 'TcpMaxDataRetransmissions' }
    its('TcpMaxDataRetransmissions') { should cmp <= 3 }
  end
end
