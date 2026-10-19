control 'SV-258046' do
  title 'RHEL 9 system accounts must not have an interactive login shell.'
  desc 'Ensuring shells are not given to system accounts upon login makes it more difficult for attackers to make use of system accounts.'
  desc 'check', %q(Verify that RHEL 9 system accounts do not have an interactive login shell.

Run the following command to list any system account (UID < 1000) that has an interactive shell, excluding authorized system utility accounts (root, sync, shutdown, halt):

$ $ awk -F: '(($3 > 0 && $3 < 1000) && $1 !~ /^(halt|sync|shutdown)$/ && $7 !~ /(nologin|false)$/) {print $1 ":" $3 ":" $7}' /etc/passwd

If the command returns any output, this is a finding.)
  desc 'fix', 'Configure RHEL 9 so that all noninteractive accounts on the system do not have an interactive shell assigned to them.

If the system account needs a shell assigned for mission operations, document the need with the information system security officer (ISSO).

Run the following command to disable the interactive shell for a specific noninteractive user account:

$ sudo usermod --shell /usr/sbin/nologin <user>'
  impact 0.5
  tag check_id: 'C-61787r1262019_chk'
  tag severity: 'medium'
  tag gid: 'V-258046'
  tag rid: 'SV-258046r1268251_rule'
  tag stig_id: 'RHEL-09-411035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61711r1262020_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  ignore_shells = input('non_interactive_shells').join('|')
  non_interactive_shells = passwd.where { uid.to_i < 1000 && !shell.match(ignore_shells) }.users - input('exempt_interactive_system_accounts')

  describe 'Non-interactive system accounts' do
    it 'should have non-interactive shells' do
      expect(non_interactive_shells).to be_empty, "Non-interactive system accounts with interactive shells:\n\t- #{non_interactive_shells.join("\n\t- ")}"
    end
  end
end
