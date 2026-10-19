control 'SV-257889' do
  title 'All RHEL 9 local initialization files must have mode 0740 or less permissive.'
  desc "Local initialization files are used to configure the user's shell
environment upon logon. Malicious modification of these files could compromise
accounts upon logon."
  desc 'check', 'Verify all local initialization files have a mode of "0740" or less permissive with the following command:

Note: The example will be for the "disauser" user, who has a home directory of "/home/disauser".

$ sudo find /home /root -maxdepth 2 -type f -name ".*" -perm /037 -ls

755 /home/disauser/.somepermissivefile

If any local initialization files are returned, this indicates a mode more permissive than "0740", and this is a finding.'
  desc 'fix', 'Set the mode of the local initialization files to "0740" with the following command:

Note: The example will be for the disauser user, who has a home directory of "/home/disauser".

$ sudo chmod 0740 /home/disauser/.<INIT_FILE>'
  impact 0.5
  tag check_id: 'C-61630r1184300_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257889'
  tag rid: 'SV-257889r1268251_rule'
  tag stig_id: 'RHEL-09-232045'
  tag fix_id: 'F-61554r1184301_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  ignore_shells = input('non_interactive_shells').join('|')

  homedirs = users.where { !shell.match(ignore_shells) && (uid >= 1000 || uid.zero?) }.homes
  alternate_ini_file_dirs = input('alternate_ini_file_dirs')
  ifiles = command("find #{homedirs.join(' ')} #{alternate_ini_file_dirs.join(' ')} -xdev -maxdepth 1 -name '.*' -type f -print0").stdout.split("\0")

  exempt_ini_files = input('exempt_ini_files')
  expected_mode = input('initialization_file_mode')
  failing_files = ifiles.select { |ifile| !exempt_ini_files.include?(ifile) && file(ifile).more_permissive_than?(expected_mode) }

  describe 'All RHEL 9 local initialization files' do
    it "must have mode '#{expected_mode}' or less permissive" do
      expect(failing_files).to be_empty, "Failing files:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
