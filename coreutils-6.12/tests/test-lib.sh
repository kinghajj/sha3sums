# source this file; set up for tests

# Skip this test if the shell lacks support for functions.
unset function_test
eval 'function_test() { return 11; }; function_test'
if test $? != 11; then
  echo "$0: /bin/sh lacks support for functions; skipping this test." 1>&2
  (exit 77); exit 77
fi

skip_test_()
{
  echo "$0: skipping test: $@" 1>&2
  (exit 77); exit 77
}

require_acl_()
{
  getfacl --version < /dev/null > /dev/null 2>&1 \
    && setfacl --version < /dev/null > /dev/null 2>&1 \
      || skip_test_ "This test requires getfacl and setfacl."

  id -u bin > /dev/null 2>&1 \
    || skip_test_ "This test requires a local user named bin."
}

require_ulimit_()
{
  ulimit_works=yes
  # Expect to be able to exec a program in 10MB of virtual memory,
  # but not in 20KB.  I chose "date".  It must not be a shell built-in
  # function, so you can't use echo, printf, true, etc.
  # Of course, in coreutils, I could use $top_builddir/src/true,
  # but this should be able to work for other projects, too.
  ( ulimit -v 10000; date ) > /dev/null 2>&1 || ulimit_works=no
  ( ulimit -v 20;    date ) > /dev/null 2>&1 && ulimit_works=no

  test $ulimit_works = no \
    && skip_test_ "this shell lacks ulimit support"
}

require_readable_root_()
{
  test -r / || skip_test_ "/ is not readable"
}

# Skip the current test if strace is not available or doesn't work
# with the named syscall.  Usage: require_strace_ unlink
require_strace_()
{
  test $# = 1 || framework_failure

  strace -V < /dev/null > /dev/null 2>&1 ||
    skip_test_ 'no strace program'

  strace -qe "$1" echo > /dev/null 2>&1 ||
    skip_test_ 'strace -qe "'"$1"'" does not work'
}

require_built_()
{
  skip_=no
  for i in "$@"; do
    case " $built_programs " in
      *" $i "*) ;;
      *) echo "$i: not built" 1>&2; skip_=yes ;;
    esac
  done

  test $skip_ = yes && skip_test_ "required program(s) not built"
}

uid_is_privileged_()
{
  # Make sure id -u succeeds.
  my_uid=$(id -u) \
    || { echo "$0: cannot run \`id -u'" 1>&2; return 1; }

  # Make sure it gives valid output.
  case $my_uid in
    0) ;;
    *[!0-9]*)
      echo "$0: invalid output (\`$my_uid') from \`id -u'" 1>&2
      return 1 ;;
    *) return 1 ;;
  esac
}

# Convert an ls-style permission string, like drwxr----x and -rw-r-x-wx
# to the equivalent chmod --mode (-m) argument, (=,u=rwx,g=r,o=x and
# =,u=rw,g=rx,o=wx).  Ignore ACLs.
rwx_to_mode_()
{
  case $# in
    1) rwx=$1;;
    *) echo "$0: wrong number of arguments" 1>&2
      echo "Usage: $0 ls-style-mode-string" 1>&2
      return;;
  esac

  case $rwx in
    [ld-][rwx-][rwx-][rwxsS-][rwx-][rwx-][rwxsS-][rwx-][rwx-][rwxtT-]) ;;
    [ld-][rwx-][rwx-][rwxsS-][rwx-][rwx-][rwxsS-][rwx-][rwx-][rwxtT-]+) ;;
    *) echo "$0: invalid mode string: $rwx" 1>&2; return;;
  esac

  # Perform these conversions:
  # S  s
  # s  xs
  # T  t
  # t  xt
  # The `T' and `t' ones are only valid for `other'.
  s='s/S/@/;s/s/x@/;s/@/s/'
  t='s/T/@/;s/t/x@/;s/@/t/'

  u=`echo $rwx|sed 's/^.\(...\).*/,u=\1/;s/-//g;s/^,u=$//;'$s`
  g=`echo $rwx|sed 's/^....\(...\).*/,g=\1/;s/-//g;s/^,g=$//;'$s`
  o=`echo $rwx|sed 's/^.......\(...\).*/,o=\1/;s/-//g;s/^,o=$//;'$s';'$t`
  echo "=$u$g$o"
}

skip_if_()
{
  case $1 in
    root) skip_test_ must be run as root ;;
    non-root) skip_test_ must be run as non-root ;;
    *) ;;  # FIXME?
  esac
}

require_selinux_()
{
  case `ls -Zd .` in
    '? .'|'unlabeled .')
      skip_test_ "this system (or maybe just" \
        "the current file system) lacks SELinux support"
    ;;
  esac
}

very_expensive_()
{
  if test "$RUN_VERY_EXPENSIVE_TESTS" != yes; then
    skip_test_ '
This test is very expensive, so it is disabled by default.
To run it anyway, rerun make check with the RUN_VERY_EXPENSIVE_TESTS
environment variable set to yes.  E.g.,

  env RUN_VERY_EXPENSIVE_TESTS=yes make check
'
  fi
}

expensive_()
{
  if test "$RUN_EXPENSIVE_TESTS" != yes; then
    skip_test_ '
This test is relatively expensive, so it is disabled by default.
To run it anyway, rerun make check with the RUN_EXPENSIVE_TESTS
environment variable set to yes.  E.g.,

  env RUN_EXPENSIVE_TESTS=yes make check
'
  fi
}

require_root_()
{
  uid_is_privileged_ || skip_test_ "must be run as root"
  NON_ROOT_USERNAME=${NON_ROOT_USERNAME=nobody}
}

skip_if_root_() { uid_is_privileged_ && skip_test_ "must be run as non-root"; }
error_() { echo "$0: $@" 1>&2; (exit 1); exit 1; }
framework_failure() { error_ 'failure in testing framework'; }

# Set `groups' to a space-separated list of at least two groups
# of which the user is a member.
require_membership_in_two_groups_()
{
  test $# = 0 || framework_failure

  groups=${COREUTILS_GROUPS-`(id -G || /usr/xpg4/bin/id -G) 2>/dev/null`}
  case "$groups" in
    *' '*) ;;
    *) skip_test_ '
$0: this test requires that you be a member of more than one group,
but running `id -G'\'' either failed or found just one.  If you really
are a member of at least two groups, then rerun this test with
COREUTILS_GROUPS set in your environment to the space-separated list
of group names or numbers.  E.g.,

  env COREUTILS_GROUPS='users cdrom' make check

'
     ;;
  esac
}

# Does the current (working-dir) file system support sparse files?
require_sparse_support_()
{
  test $# = 0 || framework_failure
  # Test whether we can create a sparse file.
  # For example, on Darwin6.5 with a file system of type hfs, it's not possible.
  # NTFS requires 128K before a hole appears in a sparse file.
  t=sparse.$$
  dd bs=1 seek=128K of=$t < /dev/null 2> /dev/null
  set x `du -sk $t`
  kb_size=$2
  rm -f $t
  if test $kb_size -ge 128; then
    skip_test_ 'this file system does not support sparse files'
  fi
}

mkfifo_or_skip_()
{
  test $# = 1 || framework_failure
  if ! mkfifo "$1"; then
    # Make an exception of this case -- usually we interpret framework-creation
    # failure as a test failure.  However, in this case, when running on a SunOS
    # system using a disk NFS mounted from OpenBSD, the above fails like this:
    # mkfifo: cannot make fifo `fifo-10558': Not owner
    skip_test_ 'NOTICE: unable to create test prerequisites'
  fi
}

skip_if_mcstransd_is_running_()
{
  test $# = 0 || framework_failure

  # When mcstransd is running, you'll see only the 3-component
  # version of file-system context strings.  Detect that,
  # and if it's running, skip this test.
  local ctx=$(stat --printf='%C\n' .) || framework_failure
  case $ctx in
    *:*:*:*) ;; # four components is ok
    *) # anything else probably means mcstransd is running
        skip_test_ "unexpected context '$ctx'; turn off mcstransd" ;;
  esac
}

# Skip the current test if umask doesn't work as usual.
# This test should be run in the temporary directory that ends
# up being removed via the trap commands.
working_umask_or_skip_()
{
  umask 022
  touch file1 file2
  chmod 644 file2
  perms=`ls -l file1 file2 | sed 's/ .*//' | uniq`
  rm -f file1 file2

  case $perms in
  *'
  '*) skip_test_ 'your build directory has unusual umask semantics'
  esac
}

test_dir_=$(pwd)

this_test_() { echo "./$0" | sed 's,.*/,,'; }
this_test=$(this_test_)

# This is a stub function that is run upon trap (upon regular exit and
# interrupt).  Override it with a per-test function, e.g., to unmount
# a partition, or to undo any other global state changes.
cleanup_() { :; }

t_=$("$abs_top_builddir/src/mktemp" -d --tmp="$test_dir_" cu-$this_test.XXXXXXXXXX)\
    || error_ "failed to create temporary directory in $test_dir_"

# Run each test from within a temporary sub-directory named after the
# test itself, and arrange to remove it upon exception or normal exit.
trap 'st=$?; cleanup_; d='"$t_"';
    cd '"$test_dir_"' && chmod -R u+rwx "$d" && rm -rf "$d" && exit $st' 0
trap '(exit $?); exit $?' 1 2 13 15

cd "$t_" || error_ "failed to cd to $t_"

if ( diff --version < /dev/null 2>&1 | grep GNU ) 2>&1 > /dev/null; then
  compare() { diff -u "$@"; }
elif ( cmp --version < /dev/null 2>&1 | grep GNU ) 2>&1 > /dev/null; then
  compare() { cmp -s "$@"; }
else
  compare() { cmp "$@"; }
fi

# Local Variables:
# indent-tabs-mode: nil
# End:
