control 'SV-258230' do
  title 'RHEL 9 must enable FIPS mode.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government because this provides assurance they have been tested and validated.'
  desc 'check', 'Verify RHEL 9 is in FIPS mode with the following command:

$ cat /proc/sys/crypto/fips_enabled
1

If the command does not return "1", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to implement FIPS mode.

If this check fails on an installed system, it is a permanent finding until the system is reinstalled with "fips=1" during installation.'
  impact 0.7
  tag check_id: 'C-61971r1184332_chk'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000478-GPOS-00223']
  tag gid: 'V-258230'
  tag rid: 'SV-258230r1268222_rule'
  tag stig_id: 'RHEL-09-671010'
  tag fix_id: 'F-61895r1184333_fix'
  tag cci: ['CCI-000068', 'CCI-000877', 'CCI-002418', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'MA-4 c', 'SC-8', 'SC-13 b']
  tag 'host'

  if virtualization.container_system?
    impact 0.0
    describe 'Control not applicable in a container' do
      skip 'The host OS controls the FIPS mode settings. The host OS should also be scanned with the applicable OS validation profile.'
    end
  elsif input('use_fips') == false
    impact 0.0
    describe 'This control is Not Applicable as FIPS is not required for this system' do
      skip 'This control is Not Applicable as FIPS is not required for this system'
    end
  else
    describe command('fips-mode-setup --check') do
      its('stdout.strip') { should match(/FIPS mode is enabled/) }
    end
  end
end
