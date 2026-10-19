control 'SV-258053' do
  title "All RHEL 9 local interactive user home directories must be group-owned by the home directory owner's primary group."
  desc 'If the Group Identifier (GID) of a local interactive users home directory is not the same as the primary GID of the user, this would allow unauthorized access to the users files, and users that share the same group may not be able to access files that they legitimately should.'
  desc 'check', %q(Verify the assigned home directory of all local interactive users is group-owned by that user's primary GID with the following command:

Note: This may miss local interactive users that have been assigned a privileged user identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information. The returned directory "/home/disauser" is used as an example.

$ getent passwd | awk -F: '($3>=1000 && $7!~/(nologin|false)$/){printf "User: %-15s Primary GID: %-5s Home: %s\\n", $1, $4, $6}'
User: disauser        Primary GID: 1002  Home: /home/disauser

Check the user's primary group with the following command:

$ stat -c "Directory: %n --> Actual GID: %g (%G)" /home/disauser
Directory: /home/disauser --> Actual GID: 1002 (disauser)

If the user home directory referenced in "/etc/passwd" is not group-owned by that user's primary GID, this is a finding.)
  desc 'fix', %q(Change the group owner of a local interactive user's home directory to the group found in "/etc/passwd". To change the group owner of a local interactive user's home directory, use the following command:

Note: The example will be for the user "disauser", who has a home directory of "/home/disauser", and has a primary group of users.

$ sudo chgrp users /home/disauser)
  impact 0.5
  tag check_id: 'C-61794r1208480_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258053'
  tag rid: 'SV-258053r1268251_rule'
  tag stig_id: 'RHEL-09-411070'
  tag fix_id: 'F-61718r1184317_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  exempt_home_users = input('exempt_home_users')
  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  iuser_entries = passwd.where { uid.to_i >= uid_min && shell !~ /nologin/ && !exempt_home_users.include?(user) }

  if !iuser_entries.users.nil? && !iuser_entries.users.empty?
    failing_iusers = iuser_entries.entries.reject { |iu|
      file(iu['home']).gid == iu.gid.to_i
    }
    failing_homedirs = failing_iusers.map { |iu| iu['home'] }

    describe 'All non-exempt interactive user account home directories on the system' do
      it 'should be group-owned by the group of the user they are associated with' do
        expect(failing_homedirs).to be_empty, "Failing home directories:\n\t- #{failing_homedirs.join("\n\t- ")}"
      end
    end
  else
    describe 'No non-exempt interactive user accounts' do
      it 'were detected on the system' do
        expect(true).to eq(true)
      end
    end
  end
end
