control 'SV-279936' do
  title 'RHEL 9 must audit any script or executable called by cron as root or by any privileged user.'
  desc 'Any script or executable called by cron as root or by any privileged user must be owned by that user. It must also have the permissions 755 or more restrictive and should have no extended rights that allow any nonprivileged user to modify the script or executable.'
  desc 'check', 'Verify RHEL 9 is configured to audit the execution of any system call made by cron as root or by any privileged user with the following command:

$ sudo auditctl -l | grep crond_t
-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec
-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec
-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec
-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec

If this command does not return the expected output, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to audit the execution of any system call made by cron as root or by any privileged user.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec
-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec
-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec
-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-84496r1210928_chk'
  tag severity: 'medium'
  tag gid: 'V-279936'
  tag rid: 'SV-279936r1210929_rule'
  tag stig_id: 'RHEL-09-654097'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-84401r1210917_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  audit_paths = ['/etc/cron.d', '/var/spool/cron']

  describe 'Cron directories auditing' do
    audit_paths.each do |audit_path|
      it "#{audit_path} is audited properly" do
        audit_rule = auditd.file(audit_path)
        expect(audit_rule).to exist
        expect(audit_rule.permissions.flatten).to include('w', 'a')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_path])
      end
    end
  end
end
