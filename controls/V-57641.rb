control 'V-57641' do
  title "Protection methods such as TLS, encrypted VPNs, or IPSEC must be
  implemented if the data owner has a strict requirement for ensuring data
  integrity and confidentiality is maintained at every step of the data transfer
  and handling process."
  desc "Information can be either unintentionally or maliciously disclosed or
  modified during preparation for transmission, for example, during aggregation,
  at protocol transformation points, and during packing/unpacking.  These
  unauthorized disclosures or modifications compromise the confidentiality or
  integrity of the information.

  Ensuring the confidentiality of transmitted information requires the
  operating system to take measures in preparing information for transmission.
  This can be accomplished via access control and encryption.

  Use of this requirement will be limited to situations where the data owner
  has a strict requirement for ensuring data integrity and confidentiality is
  maintained at every step of the data transfer and handling process. When
  transmitting data, operating systems need to support transmission protection
  mechanisms such as TLS, encrypted VPNs, or IPSEC.
  "
  impact 0.5
  tag "gtitle": 'WIN00-000019'
  tag "gid": 'V-57641'
  tag "rid": 'SV-72051r1_rule'
  tag "stig_id": 'WN12-00-000019'
  tag "fix_id": 'F-62843r3_fix'
  tag "cci": ['CCI-002420', 'CCI-002422']
  tag "nist": ['SC-8 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the data owner has a strict requirement for ensuring data
  integrity and confidentiality is maintained at every step of the data transfer
  and handling process, verify protection methods such as TLS, encrypted VPNs, or
  IPSEC have been implemented.  If protection methods have not been implemented,
  this is a finding."
  tag "fix": "Configure protection methods such as TLS, encrypted VPNs, or
  IPSEC when the data owner has a strict requirement for ensuring data integrity
  and confidentiality is maintained at every step of the data transfer and
  handling process to maintain the confidentiality and integrity."
  describe "Protection methods such as TLS, encrypted VPNs, or IPSEC must be
  implemented if the data owner has a strict requirement for ensuring data
  integrity and confidentiality is maintained at every step of the data transfer
  and handling process." do
    skip 'is a manual check'
  end
end
