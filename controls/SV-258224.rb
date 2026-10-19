control 'SV-258224' do
  title 'RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/faillock.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Verify RHEL 9 generates audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/faillock" with the following command:

$ sudo auditctl -l | grep /var/log/faillock
-a always,exit -F arch=b32 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins
-a always,exit -F arch=b64 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/faillock".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins
-a always,exit -F arch=b64 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-61965r1210910_chk'
  tag severity: 'medium'
  tag gid: 'V-258224'
  tag rid: 'SV-258224r1210926_rule'
  tag stig_id: 'RHEL-09-654250'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-61889r1210911_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  audit_command = '/var/log/faillock'
  audit_archs = os.arch.match(/64/) ? ['b32', 'b64'] : ['b32']

  describe 'Command' do
    audit_archs.each do |audit_arch|
      it "#{audit_command} is audited properly for #{audit_arch}" do
        # syscall rules on -F path= only; a bare -w watch (no fields) does not satisfy the requirement
        audit_rule = auditd.file(audit_command).where { Array(fields).include?("arch=#{audit_arch}") }
        expect(audit_rule).to exist
        expect(audit_rule.action.uniq).to cmp 'always'
        expect(audit_rule.list.uniq).to cmp 'exit'
        expect(audit_rule.permissions.flatten).to include('w', 'a')
        expect(audit_rule.fields.flatten).to include('auid>=1000')
        expect(audit_rule.fields.flatten & ['auid!=unset', 'auid!=-1', 'auid!=4294967295']).not_to be_empty
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
      end
    end
  end
end
