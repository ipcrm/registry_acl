# The enable-privilege function was copied from 
# https://social.technet.microsoft.com/Forums/windowsserver/en-US/e718a560-2908-4b91-ad42-d392e7f8f1ad/take-ownership-of-a-registry-key-and-change-permissions?forum=winserverpowershell
# 
function enable-privilege {
 param(
  ## The privilege to adjust. This set is taken from
  ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
  [ValidateSet(
   "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
   "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
   "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
   "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
   "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
   "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
   "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
   "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
   "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
   "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
   "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
  $Privilege,
  ## The process on which to adjust the privilege. Defaults to the current process.
  $ProcessId = $pid,
  ## Switch to disable the privilege, rather than enable it.
  [Switch] $Disable
 )

 ## Taken from P/Invoke.NET with minor adjustments.
 $definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

 $processHandle = (Get-Process -id $ProcessId).Handle
 $type = Add-Type $definition -PassThru
 $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}


Function Set-RegOwner {
    <#
        .SYNOPSIS
            Take ownership of a registry key.

        .DESCRIPTION
            Changes owner of a registry path another user or group.  This is an adapted version of set-owner originally written by Boe Prox(Hey, Scripting Guy!)

        .PARAMETER Path
            The registry key to update

        .PARAMETER Account
            The new owner account (Fully qualified, such as BUILTIN\Administrators)
    #>
    [cmdletbinding(
        SupportsShouldProcess = $True
    )]
    Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [string[]]$Path,
        [parameter()]
        [string]$Account = 'Builtin\Administrators',
        ## The process on which to adjust the privilege. Defaults to the current process.
        $ProcessId = $pid
    )
    Begin {
        #Prevent Confirmation on each Write-Debug command when using -Debug
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
        Try {

        } Catch {
        }

    }
    Process {
        # The Path param can be split into two, the first part is the registry, the second part is the path
        $target_path = $Path.split(":")
        $reg_path = $target_path[1]
        $reg_class = switch ($target_path[0]) {
            'HKEY_CLASSES_ROOT' { "ClassesRoot"; break }
            'HKEY_LOCAL_MACHINE' { "LocalMachine"; break }
            'HKEY_USERS' { "Users"; break }
        }
        $key = [Microsoft.Win32.Registry]::$reg_class.OpenSubKey("$reg_path",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::takeownership)
        # You must get a blank acl for the key b/c you do not currently have access
        $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
        $me = [System.Security.Principal.NTAccount]"$Account"
        $acl.SetOwner($me)
        $key.SetAccessControl($acl)
        # After you have set owner you need to get the acl with the perms so you can modify it.
        $acl = $key.GetAccessControl()
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("$Account","FullControl","Allow")
        $acl.SetAccessRule($rule)
        $key.SetAccessControl($acl)
        $key.Close()
    }
    End {
    }
}