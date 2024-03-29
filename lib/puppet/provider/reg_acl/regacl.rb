# frozen_string_literal: true

require 'puppet/provider/regpowershell'
require 'json'
begin
  require 'win32/registry'
rescue LoadError
  puts 'This does not appear to be a Windows system.  Provider may not function.'
end

Puppet::Type.type(:reg_acl).provide(:regacl, parent: Puppet::Provider::Regpowershell) do
  confine operatingsystem: :windows
  defaultfor operatingsystem: :windows

  def initialize(value = {})
    super(value)
    @property_flush = {}
    @acl_hash = {}
    @mount_drive_cmd = ''.dup
    @capability_acl_hash = {}
  end

  def account_name(sid)
    # Capability SIDs were introduced with Windows 8.  Permissions for these identities cannot be managed
    #  through the GUI or PowerShell, as they are intentionally not resolvable.
    #  https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers#capability-sids
    #  https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
    #   - see "Capability SIDs" at the end of the document, and the associated note.
    if sid.to_s.start_with? 'S-1-15-3-'
      name = sid.to_s
    else
      name = Puppet::Util::Windows::SID.sid_to_name(sid)
      # The APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES will not resolve to a SID properly - See PUP-2985
      name = name.to_s.split(%r{\\})[1] if name.to_s.include?('APPLICATION PACKAGE AUTHORITY')
      raise "Reg_acl: account_name could not find a account for sid #{sid}" if name.nil?
    end
    name
  end

  def purge_state
    @resource[:purge].downcase.to_sym
  end

  def account_sid(account)
    # Nasty Hack space...
    # The APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES will not resolve to a SID properly - See PUP-2985
    account = account.to_s.split(%r{\\})[1] if account.to_s.include?('APPLICATION PACKAGE AUTHORITY')
    # Capability SIDs were introduced with Windows 8.  Permissions for these identities cannot be managed
    #  through the GUI or PowerShell, as they are intentionally not resolvable.
    #  https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers#capability-sids
    #  https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
    #   - see "Capability SIDs" at the end of the document, and the associated note.
    if account.to_s.start_with? 'S-1-15-3-'
      sid = account.to_s
    else
      sid = Puppet::Util::Windows::SID.name_to_sid(account)
      raise "Reg_acl: account_sid could not find a SID for account #{account}" if sid.nil?
    end
    sid
  end

  def access_control_type(accesscontroltype)
    return 'Allow' if accesscontroltype.zero?

    return 'Deny' if accesscontroltype == 1

    return 0 if accesscontroltype.eql?('Allow')

    return 1 if accesscontroltype.eql?('Deny')

    raise "Unknown AccessControlType #{accesscontroltype}"
  end

  def get_perm(arg)
    numperms = {
      1              => 'QueryValues',
      2              => 'SetValue',
      4              => 'CreateSubKey',
      8              => 'EnumerateSubKeys',
      16             => 'Notify',
      32             => 'CreateLink',
      131_097        => 'ReadKey',
      131_078        => 'WriteKey',
      65_536         => 'Delete',
      131_072        => 'ReadPermissions',
      262_144        => 'ChangePermissions',
      524_288        => 'TakeOwnership',
      983_103        => 'FullControl',
      268_435_456    => 'GENERIC_ALL',
      1_073_741_824  => 'GENERIC_WRITE',
      536_870_912    => 'GENERIC_EXECUTE',
      -2_147_483_648 => 'GENERIC_READ',
    }

    if arg.is_a?(Integer)
      return numperms[arg] if numperms.key?(arg)

      perm = []
      numperms.each do |k, v|
        if k & arg == k
          perm.push(v)
        end
      end
      perm.sort.join(', ')

    elsif arg.is_a?(String)
      perm = Integer.new
      defined_perms = arg.split(%r{,})
      defined_perms.each do |p|
        pmask = numperms.rassoc(p)
        raise("Invalid permission - #{p}") if pmask.nil?
        perm |= pmask
      end
      perm
    else
      raise("Invalid permission type - #{arg.class}")
    end
  end

  def get_inherit(arg)
    inheritflags = {
      0 => 'None',
      1 => 'ContainerInherit',
      3 => 'ContainerInherit, ObjectInherit',
    }

    begin
      inheritflags.key?(arg) ? inheritflags[arg] : inheritflags.rassoc(arg)
    rescue
      raise("Invalid Inheritance set - #{arg}")
    end
  end

  def get_propagate(arg)
    propagateflags = {
      0 => 'None',
      2 => 'InheritOnly',
      3 => 'NoPropagateInherit, InheritOnly',
    }

    begin
      propagateflags.key?(arg) ? propagateflags[arg] : propagateflags.rassoc(arg)
    rescue
      raise("Invalid Propagate Flags set - #{arg}")
    end
  end

  def get_target_full_path(value)
    target = value.split(%r{[:,\\]})
    case target[0].downcase
      # Source https://github.com/puppetlabs/puppetlabs-registry/blob/master/lib/puppet_x/puppetlabs/registry.rb#L93
    when %r{hkey_local_machine}, %r{hklm}
      target[0] = 'HKEY_LOCAL_MACHINE'
    when %r{hkey_classes_root}, %r{hkcr}
      target[0] = 'HKEY_CLASSES_ROOT'
      @mount_drive_cmd << <<-ps1.gsub(%r{^\s+}, '')
          new-psdrive -name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-null
          new-psdrive -name HKEY_CLASSES_ROOT -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-null
        ps1
    when %r{hkey_users}, %r{hku}
      target[0] = 'HKEY_USERS'
      @mount_drive_cmd << <<-ps1.gsub(%r{^\s+}, '')
          new-psdrive -name HKU -PSProvider Registry -Root HKEY_USERS | Out-null
          new-psdrive -name HKEY_USERS -PSProvider Registry -Root HKEY_USERS | Out-null
        ps1
    when %r{hkey_current_user}, %r{hkcu},
        %r{hkey_current_config}, %r{hkcc},
        %r{hkey_performance_data},
        %r{hkey_performance_text},
        %r{hkey_performance_nlstext},
        %r{hkey_dyn_data}
      raise ArgumentError, "Unsupported predefined key: #{path}"
    else
      raise ArgumentError, "Invalid registry key: #{target[0]}"
    end

    Puppet.debug "Reg_acl: get_target_full_path - new path #{target}"
    target
  end

  def acl_info
    target = @resource[:target]
    Puppet.debug "Reg_acl: Enter acl_info, target - #{target}"

    if @acl_hash.empty?
      # Check if the key exists, return false if it doesn't
      targetarr = get_target_full_path(target)
      begin
        access = Win32::Registry::KEY_READ
        case targetarr[0].downcase
        when %r{hkey_local_machine}
          @acl_hash[:key_exists] = true unless Win32::Registry::HKEY_LOCAL_MACHINE.open(targetarr[1..-1].join('\\'), access).nil?
        when %r{hkey_classes_root}
          @acl_hash[:key_exists] = true unless Win32::Registry::HKEY_CLASSES_ROOT.open(targetarr[1..-1].join('\\'), access).nil?
        when %r{hkey_users}
          @acl_hash[:key_exists] = true unless Win32::Registry::HKEY_USERS.open(targetarr[1..-1].join('\\'), access).nil?
        end
      rescue
        raise "Target Registry Key doesn't exist!"
      end

      owner_cmd = "(get-acl '#{target}').owner"
      owner = Puppet::Type::Reg_acl::ProviderRegacl.run(owner_cmd, @mount_drive_cmd)
      Puppet.debug "Reg_acl: #{target} current owner: #{owner}"
      @acl_hash[:owner] = account_sid(owner.chomp)

      acelist_cmd = "(get-acl '#{target}').access | convertto-json -Compress"
      acelist = JSON.parse(Puppet::Type::Reg_acl::ProviderRegacl.run(acelist_cmd, @mount_drive_cmd))
      Puppet.debug "Reg_acl: #{target} current ACE list: #{acelist}"

      newace = []
      capabilityace = []
      inherit = false

      # acelist is not an array of hashes if there is only one ACE; need to convert it
      acelist = [acelist] if acelist.class == Hash
      acelist.each do |v|
        # If even one ACE is inherited, we know that we are inherting
        if v['IsInherited'] == true
          inherit = true
        end

        begin
          tace = {}
          tace['RegistryRights']    = get_perm(v['RegistryRights'])
          tace['AccessControlType'] = access_control_type(v['AccessControlType'])
          tace['IdentityReference'] = account_sid(v['IdentityReference']['Value'])
          tace['IsInherited']       = v['IsInherited']
          tace['InheritanceFlags']  = get_inherit(v['InheritanceFlags'])
          tace['PropagationFlags']  = get_propagate(v['PropagationFlags'])
        rescue => ex
          # Need a notice message here that indicates what went wrong and
          # that a pre-existing acl is being ignored.
          Puppet.debug "Exception caught: #{ex.inspect}"
          Puppet.notice "Pre-existing ACL on: #{target} #{v.inspect} Ignored due to: #{ex.inspect}"
        else
          # Remove ACE for capability SIDs from CURRENT so comparisons are valid.
          if v['IdentityReference']['Value'].start_with?('S-1-15-3-')
            capabilityace.push(tace)
          else
            newace.push(tace)
          end
        end
      end

      @acl_hash[:permissions] = newace
      @capability_acl_hash[:permissions] = capabilityace
      @acl_hash[:inherit_from_parent] = inherit
    end

    @acl_hash
  end

  def are_permissions_insync?(current, should)
    purge = @resource[:purge].downcase.to_sym

    current.sort_by! { |m| m['IdentityReference'] }
    should.sort_by! { |m| m['IdentityReference'] }

    Puppet.debug "Reg_acl: Permissions Insync? Check; Current - #{current}"
    Puppet.debug "Reg_acl: Permissions Insync? Check; Should - #{should}"

    if purge == :all
      Puppet.debug "Intersect, purge all, - #{current & should}"
      # If we are purging everything (ie declaring all ACE that should be present) -
      # should will be equivalent to current
      current == should
    elsif purge == :listed
      Puppet.debug "Intersect, purge listed, - #{current & should}"
      # If we are only removing the declared ACE (if they exist), the intersection will be
      # empty if the appropriate ACE are not present
      (current & should).empty?
    else
      Puppet.debug "Intersect, purge false, - #{current & should}"
      # If purge isn't set; the intersection of current and should will contain all required
      # ACE if it is correct
      (current & should) == should
    end
  end

  def owner
    acl_info[:owner]
  end

  def owner=(value)
    @property_flush[:owner] = value
  end

  def owner_to_s(value)
    account_name(value)
  end

  def inherit_from_parent
    acl_info[:inherit_from_parent]
  end

  def inherit_from_parent=(value)
    @property_flush[:inherit_from_parent] = value
  end

  def permissions
    acl_info[:permissions]
  end

  def permissions=(value)
    @property_flush[:permissions] = value
  end

  def permissions_to_s(value)
    newvalue = []
    value.each do |p|
      newhash = {}
      p.each do |k, v|
        newhash[k] = if k == 'IdentityReference'
                       account_name(v)
                     else
                       v
                     end
      end
      newvalue.push(newhash)
    end
    newvalue
  end

  def self.instances
    []
  end

  def exists?
    acl_info[:key_exists].downcase.to_sym == :true
  end

  def create
    raise Puppet::Error, "Cannot create target registry keys - '#{@resource[:target]}' doesn't exist." unless key_exists?(@resource[:target])
  end

  def destroy
    raise Puppet::Error, 'Cannot remove target registry keys - only set permissions.' unless @resource[:permissions]
  end

  def ace_rule_builder
    cmd = ''.dup

    ace_method = if @resource[:purge].downcase.to_sym == :listed
                   'RemoveAccessRule'
                 else
                   'AddAccessRule'
                 end

    # If purging all so only SHOULD is applied, we need to modify the existing ACL
    #   around any capability SIDs rather than replacing the entire ACL.
    #   Remove all ACEs except capability SIDS before adding desired ACEs.
    if @resource[:purge]. downcase.to_sym == :all
      cmd << <<-ps1.gsub(%r{^\s+}, '')
        $filteredAces = $objACL.Access | where-object { $_.IdentityReference -notlike "S-1-15-3-*"}
        foreach ($tmpACE in $filteredAces) {
          if ($tmpAce.IdentityReference -like 'APPLICATION PACKAGE AUTHORITY*') {
              $secPrincipal = $tmpACE.identityreference.ToString().split('\\')[1]
              $InheritanceFlag = $tmpACE.InheritanceFlags
              $PropagationFlag = $tmpACE.PropagationFlags
              $objAccess       = $tmpAce.RegistryRights
              $objType         = $tmpACE.AccessControlType
              $AceToRemove = New-Object System.Security.AccessControl.RegistryAccessRule ($secPrincipal,$objAccess,$InheritanceFlag,$PropagationFlag,$objType)
          } else { $AceToRemove = $tmpACE }
          $objACL.RemoveAccessRule($AceToRemove) | out-null
        }
      ps1
    end

    @property_flush[:permissions].each do |p|
      # If we adding, we need to clear out any existing ace that doesn't match
      if @resource[:purge].downcase.to_sym == :false
        cmd << <<-ps1.gsub(%r{^\s+}, '')
          $acesToRemove = $objACL.Access | where-object { $_.IsInherited -eq $false -and $_.IdentityReference -eq '#{account_name(p['IdentityReference'])}' }
          if ($acesToRemove) { $objACL.RemoveAccessRule($acesToRemove) }
        ps1
      end

      next unless p['IsInherited'] == false
      cmd << <<-ps1.gsub(%r{^\s+}, '')
          $secPrincipal    = '#{account_name(p['IdentityReference'])}'
          $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]'#{p['InheritanceFlags']}'
          $PropagationFlag = [System.Security.AccessControl.PropagationFlags]'#{p['PropagationFlags']}'
          $objAccess       = [System.Security.AccessControl.RegistryRights]'#{p['RegistryRights']}'
          $objType         = [System.Security.AccessControl.AccessControlType]'#{p['AccessControlType']}'

          $objUser = New-Object System.Security.Principal.NTAccount($secPrincipal)
          $objACE = New-Object System.Security.AccessControl.RegistryAccessRule($objUser, $objAccess, $InheritanceFlag, $PropagationFlag, $objType)
          $objACL.#{ace_method}($objACE)
      ps1
    end

    cmd << <<-ps1.gsub(%r{^\s+}, '')
      Set-ACL '#{@resource[:target]}' $objACL -ErrorAction Stop
    ps1

    cmd
  end

  def flush
    # Store up one big powershell string to excute so we don't
    # suffer the performance issues with firing up ps1 shells
    cmd = ''.dup

    if @property_flush[:owner]
      Puppet.debug 'Reg_acl: Enter flush, set owner'
      cmd << <<-ps1.gsub(%r{^\s+}, '')
        Set-RegOwner '#{@resource[:target]}' -Account '#{account_name(@resource[:owner])}' -ErrorAction Stop
      ps1
    end

    if @property_flush[:permissions]
      cmd << <<-ps1.gsub(%r{^\s+}, '')
        $objACL = get-acl '#{@resource[:target]}' -ErrorAction Stop
      ps1
      cmd << ace_rule_builder
    end

    if @property_flush[:inherit_from_parent]
      Puppet.debug 'Reg_acl: Enter flush, inherit from parent'
      rule = @property_flush[:inherit_from_parent].downcase.to_sym.eql?(:true) ? '$False,$False' : '$True,$False'
      cmd << <<-ps1.gsub(%r{^\s+}, '')
        $t = get-acl '#{@resource[:target]}'
        $t.SetAccessRuleProtection(#{rule})
        Set-ACL '#{@resource[:target]}' $t -ErrorAction Stop
      ps1
    end

    unless cmd.empty?
      cmd_preface = <<-ps1.gsub(%r{^\s+}, '')
        $ErrorActionPreference = 'Stop'\n
        try {
      ps1

      cmd.prepend(cmd_preface)
      cmd << <<-ps1.gsub(%r{^\s+}, '')
        } catch {
          write-host "Failure: $($_.Exception.Message)"
          exit 1
        }
      ps1

      Puppet::Type::Reg_acl::ProviderRegacl.run(cmd, @mount_drive_cmd)
    end

    @property_flush = {}
    @acl_hash = {}
  end
end
