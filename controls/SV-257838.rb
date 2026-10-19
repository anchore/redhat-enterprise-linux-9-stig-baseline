control 'SV-257838' do
  title 'RHEL 9 must have the openssl-pkcs11 package installed.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. The DoW common access card (CAC) with DoW-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is Not Applicable.

Verify that RHEL 9 has the openssl-pkcs11 package installed with the following command:

$ dnf list --installed openssl-pkcs11

Example output:

openssl-pkcs.i686          0.4.11-7.el9
openssl-pkcs.x86_64          0.4.11-7.el9

If the "openssl-pkcs11" package is not installed, this is a finding.'
  desc 'fix', 'The openssl-pkcs11 package can be installed with the following command:

$ sudo dnf install openssl-pkcs11'
  impact 0.5
  tag check_id: 'C-61579r1044911_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000375-GPOS-00160', 'SRG-OS-000376-GPOS-00161', 'SRG-OS-000377-GPOS-00162']
  tag gid: 'V-257838'
  tag rid: 'SV-257838r1268228_rule'
  tag stig_id: 'RHEL-09-215075'
  tag fix_id: 'F-61503r925500_fix'
  tag cci: ['CCI-001948', 'CCI-000765', 'CCI-001953', 'CCI-001954', 'CCI-004046']
  tag nist: ['IA-2 (11)', 'IA-2 (1)', 'IA-2 (12)', 'IA-2 (6) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  if input('alternate_mfa_method') == ''
    describe package('openssl-pkcs11') do
      it { should be_installed }
    end
  else
    impact 0.0
    describe 'N/A' do
      skip 'The system is using an approved alternative MFA method; this control is Not Applicable.'
    end
  end
end
