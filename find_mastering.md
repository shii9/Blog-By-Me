![image1](image1)

# Mastering find / -type f: The Complete Guide to File Discovery, Recon and Forensics on Linux

*From a one-line file dump to SUID hunting, forensic timelines and integrity baselines. Every test, action and operator explained with a working example, organized the way the tool actually evaluates them.*

**By SHIx9 (Sourov Hossen)**

Most people meet `find / -type f` as a way to dump every file on a system into a pipe and move on. That treats one of the most capable tools on a Unix machine as a slower `locate`.

`find` is a tree walker with a small expression language. `find / -type f` is the simplest sentence in that language: start at the root, visit every entry, print the regular files.

Everything else (size, age, permissions, ownership, hashing, running commands) is a predicate you chain onto that sentence. For a security researcher, that means privilege escalation recon, incident response triage and integrity monitoring from one binary that ships on practically every Unix system.

This guide walks through it the way the tool actually works: how the expression is evaluated, how to survive running it against `/`, and where each test earns its place in a security workflow. Everything here is meant for systems you own or are authorized to assess.

## Scope, Conventions and Safety

> [!WARNING]
> **Authorization required.** Everything here is for systems you own, administer or have written permission to assess. The commands are read-only unless they say otherwise, but reading credential files or sweeping a production host without authorization can still break law and policy. When an assessment turns up secrets, report where they are, not what they say.

**Conventions.** Examples target GNU findutils 4.7 or newer on Linux and run in bash. Run as root for complete coverage of a host you administer, and as an ordinary user to see what a low-privilege attacker sees. The two outputs differ, and both are useful.

**How this guide is organized.**

- **Part I, Foundations (01-07):** how find evaluates an expression, and how to walk `/` without drowning.
- **Part II, Selecting files (08-14):** symlinks, names, numeric arguments, size, time, permissions, inodes and filesystem types.
- **Part III, Acting on results (15-17):** output, `-exec`, automation safety, and pairing find with other tools.
- **Part IV, Security and incident response (18-22):** privilege-escalation recon, credentials, persistence, writable locations and an IR workflow.
- **Part V, Reference (23-29):** related tools, performance, flag reference, methodology, query building, a cheat sheet and common mistakes.

## Table of Contents

- [01 · What find / -type f Actually Does](#01--what-find---type-f-actually-does)
- [02 · Versions and Installation](#02--versions-and-installation)
- [03 · Syntax and Evaluation Order](#03--syntax-and-evaluation-order)
- [04 · File Types with -type](#04--file-types-with--type)
- [05 · Taming the Root Filesystem](#05--taming-the-root-filesystem)
- [06 · Errors Are Evidence: stderr, Exit Codes and Privileges](#06--errors-are-evidence-stderr-exit-codes-and-privileges)
- [07 · Depth Control and Stopping Early](#07--depth-control-and-stopping-early)
- [08 · Symlinks: -P, -H and -L](#08--symlinks--p--h-and--l)
- [09 · Matching Names and Paths](#09--matching-names-and-paths)
- [10 · Numeric Arguments: +n, -n and n](#10--numeric-arguments-n--n-and-n)
- [11 · Size and Empty Files](#11--size-and-empty-files)
- [12 · Time](#12--time)
- [13 · Permissions and Ownership](#13--permissions-and-ownership)
- [14 · Inodes, Hard Links and Filesystem Types](#14--inodes-hard-links-and-filesystem-types)
- [15 · Actions and Safe Output](#15--actions-and-safe-output)
- [16 · Automation Security: Races, sh -c and Safe Deletion](#16--automation-security-races-sh--c-and-safe-deletion)
- [17 · Combining find with grep, xargs and Other Tools](#17--combining-find-with-grep-xargs-and-other-tools)
- [18 · Security Use Cases](#18--security-use-cases)
- [19 · Credential and Sensitive-File Discovery](#19--credential-and-sensitive-file-discovery)
- [20 · Persistence Hunting: Cron, systemd and Startup Files](#20--persistence-hunting-cron-systemd-and-startup-files)
- [21 · Writable Locations, Orphaned Files and Capabilities](#21--writable-locations-orphaned-files-and-capabilities)
- [22 · Incident Response Workflow](#22--incident-response-workflow)
- [23 · Related Tools](#23--related-tools)
- [24 · Performance](#24--performance)
- [25 · Full Flag Reference](#25--full-flag-reference)
- [26 · Real Methodology: Putting It Together](#26--real-methodology-putting-it-together)
- [27 · Building Queries in Layers](#27--building-queries-in-layers)
- [28 · Command Cheat Sheet](#28--command-cheat-sheet)
- [29 · Common Mistakes](#29--common-mistakes)

## 01 · What find / -type f Actually Does

Break the command into its parts:

- `find` is the program.
- `/` is the starting point. find descends into every directory beneath it.
- `-type f` is a **test**. It is true only for regular files, so directories, symlinks, sockets, pipes and device nodes are skipped.
- There is no action, so find appends an implicit `-print`.

Three consequences matter in practice:

- **It is live, not indexed.** `locate` reads a database built earlier by `updatedb`. find reads the filesystem right now. It is slower, but it never lies about a file created ten seconds ago, which is exactly what you need during incident response.
- **Output is unsorted.** Entries come out in directory order. If order matters, sort explicitly.
- **Errors do not stop the walk.** Every unreadable directory prints `Permission denied` to stderr, the walk continues, and find exits non-zero at the end. In scripts, that exit code is not a reliable success signal.

**Mental model:** think of find as a `SELECT` over the filesystem. The starting points are `FROM`, the tests are `WHERE`, and the actions decide what happens to each matching row.

## 02 · Versions and Installation

Three implementations are common, and they are not interchangeable:

- **GNU findutils** is the default on Linux and the reference for everything below.
- **BSD find** ships with macOS and FreeBSD. It lacks `-printf` and `-regextype`.
- **BusyBox find** is on Alpine, routers and embedded devices. It supports a reduced feature set.

```
find --version        # GNU prints a version, BSD errors out
sudo apt install findutils      # Debian, Ubuntu, Kali
brew install findutils          # macOS, installs as gfind
apk add findutils               # Alpine, replaces the BusyBox applet
```

The documentation worth knowing:

- `man find` for the reference page
- `info find` for the longer GNU manual
- `find --help` for a flag summary
- The online GNU manual: https://www.gnu.org/software/findutils/manual/html\_mono/find.html

## 03 · Syntax and Evaluation Order

```
find [-H|-L|-P] [-D debugopts] [-Olevel] [starting-point...] [expression]
```

The expression is built from four kinds of pieces:

- **Global options** such as `-maxdepth`, `-xdev` and `-depth` affect the whole walk. Put them before tests or GNU find warns you.
- **Tests** return true or false: `-type`, `-name`, `-size`, `-perm`, `-mtime`.
- **Actions** do something: `-print`, `-exec`, `-delete`, `-ls`.
- **Operators** combine them: `!` (not), `-a` (and), `-o` (or), `\( \)` (grouping).

Two rules drive most bugs. First, adjacent tests are joined by an implicit `-a`. Second, evaluation is left to right with short-circuiting: if a test fails, everything after it in that `-a` chain is skipped for that file. Precedence is `!`, then `-a`, then `-o`.

Here is the classic mistake:

```
# Wrong: -print only binds to the second -name
find / -name '*.bak' -o -name '*.old' -print

# Right: group the alternatives
find / \( -name '*.bak' -o -name '*.old' \) -print
```

You can pass several starting points in one command, such as `find /etc /var/www -type f`. The parentheses must be escaped or quoted so the shell does not eat them.

## 04 · File Types with -type

- `f` regular file
- `d` directory
- `l` symbolic link
- `b` block device
- `c` character device
- `p` named pipe (FIFO)
- `s` socket
- `D` Solaris door

Newer GNU findutils (4.7+) accept a comma-separated list, so `-type f,l` matches regular files and symlinks in one test.

`-xtype` is the same test applied to what a symlink points at. `find / -xtype l` lists broken symlinks, which is a useful check for dangling links in privileged paths.

## 05 · Taming the Root Filesystem

Running `find / -type f` as-is is noisy and often wasteful. Work through it in layers.

**Step 1: silence the noise and see the scale.**

```
find / -type f 2>/dev/null | wc -l
```

`2>/dev/null` hides permission errors. Run it as root and most of them disappear anyway.

**Step 2: stay on one filesystem with -xdev.**

```
find / -xdev -type f 2>/dev/null
```

`-xdev` (alias `-mount`) refuses to cross mount points. That skips `/proc`, `/sys` and network mounts. It also skips any separate partition such as `/home` or `/var`, so check `findmnt` first and list those mounts as extra starting points: `find / /home /var -xdev -type f`.

**Step 3: prune what you do not want.**

```
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f -print 2>/dev/null
```

`-prune` means do not descend into this directory. The explicit `-print` at the end is required. Without it the implicit print wraps the whole expression, and the pruned directories themselves get printed.

You can also prune by filesystem type: `\( -fstype proc -o -fstype sysfs -o -fstype nfs -o -fstype cifs \) -prune -o -type f -print`.

**Why `/proc` is a trap.** Entries there are generated by the kernel on read. Files report zero size, per-process trees explode the file count, and some entries lie. `/proc/kcore` shows up as a regular file with an enormous apparent size, so it will pollute any `-size +1G` search.

## 06 · Errors Are Evidence: stderr, Exit Codes and Privileges

`2>/dev/null` is the reflex fix for the wall of `Permission denied` messages, and during quick recon it is fine. During an investigation it throws away information. Capture stderr instead and read it:

```
find / -xdev -type f >results.txt 2>errors.log
wc -l results.txt errors.log
sort errors.log | uniq -c | sort -rn | head
```

The error log is a map of what you could not see: home directories you cannot traverse, hardened paths, and files that vanished mid-walk.

`No such file or directory` on a live system is normal, especially under `/tmp` and `/proc`, and GNU find's `-ignore_readdir_race` silences it if you want it gone.

**Exit codes.** find exits `0` only if every path was processed without error. One unreadable directory makes the exit code non-zero even when the results are complete for your purposes. In scripts, do not treat `find ... && next-step` as a success check on a live filesystem. Check the output, or tolerate specific errors.

**Run it twice: unprivileged and privileged.** The difference is itself a finding.

```
find / -xdev -type f -perm -4000 2>/dev/null | sort > suid_user.txt
sudo find / -xdev -type f -perm -4000 2>/dev/null | sort > suid_root.txt
diff suid_user.txt suid_root.txt
```

Anything in the second list but not the first lives inside a directory the unprivileged account cannot traverse. That shows you what a low-privilege attacker cannot even enumerate, which is exactly the boundary a hardening review wants to confirm.

> [!CAUTION]
> When you use `sudo find`, the command runs with full privileges, and so does anything you attach with `-exec` or `-delete`.

## 07 · Depth Control and Stopping Early

Walking the whole tree is rarely the first thing you need. Limit the walk, then widen it.

```
find /etc -maxdepth 1 -type f                     # direct children only
find /etc -maxdepth 2 -type f                     # one level deeper
find /var/log -mindepth 1 -maxdepth 2 -type f     # skip the start point, stop at depth 2
```

- `-maxdepth N` stops descent below depth N. Depth `0` is the starting point itself, depth `1` its direct children.
- `-mindepth N` suppresses results above depth N. `-mindepth 1` excludes the starting points.
- Both are global options. Place them before your tests, or GNU find warns, because they affect the whole walk and not just the tests to their left.
- `-depth` makes find process a directory's contents before the directory itself. `-delete` turns it on implicitly, which is why `-delete` and `-prune` do not mix: with `-depth` active, `-prune` has no effect.

**Survey before you search.** `find / -xdev -maxdepth 2 -type d` shows you the layout of an unfamiliar host in seconds and tells you where to aim the expensive queries.

**Stop at the first hit.** `-quit` exits find immediately. Put an action before it, or nothing prints:

```
find / -xdev -name ssh_config -print -quit 2>/dev/null
find /var/www -type f -newermt '2026-10-01' -print -quit | grep -q . && echo 'changed files exist'
```

The second form is a cheap existence test for scripts: find does no more work once it has an answer.

## 08 · Symlinks: -P, -H and -L

- `-P` is the default. Symlinks are never followed, and a symlink is type `l`.
- `-H` follows symlinks only for starting points given on the command line.
- `-L` follows every symlink. A link to a regular file then reports as type `f`.

```
find / -xdev -L -type f 2>/dev/null
```

Be careful with `-L`. It can loop, and it can walk out of the tree you meant to scan. For security work, the default `-P` is usually correct because you want to see links as links.

**Merged-`/usr` systems.** On many current distributions `/bin`, `/sbin` and `/lib` are symlinks into `/usr`. With the default `-P`, find reports a symlink given as a starting point and does not descend into it. Use `-H`, which follows symlinks named on the command line and nothing deeper, or pass the real path: `find -H /bin /sbin -type f`.

## 09 · Matching Names and Paths

```
find / -xdev -type f -name '*.conf' 2>/dev/null
find / -xdev -type f -iname 'readme*' 2>/dev/null
find /var/www -type f -path '*/uploads/*' -name '*.php'
find / -xdev -type f -regextype posix-extended -regex '.*\.(pem|key|crt)$' 2>/dev/null
```

- `-name` matches only the final path component, with shell-style globs. A slash can never match.
- `-iname` is the case-insensitive version.
- `-path` matches the whole path, and `*` happily crosses slashes.
- `-regex` must match the **entire** path, not a fragment. The default flavor is Emacs-style, so set `-regextype posix-extended` if you think in ERE.
- **Always quote globs.** An unquoted `*.conf` can be expanded by the shell in the current directory before find ever sees it.

## 10 · Numeric Arguments: +n, -n and n

Many tests take a number, and they all share one convention. Learn it once and `-mtime`, `-size`, `-links`, `-uid` and the rest read the same way.

| Form | Meaning | Example |
| --- | --- | --- |
| `+n` | greater than n | `-mtime +7` (older than 7 full days) |
| `-n` | less than n | `-size -10k` (under 10 KiB after rounding up) |
| `n` | exactly n | `-links 3` (exactly three hard links) |

The same rule applies to `-atime`, `-ctime`, `-mmin`, `-amin`, `-cmin`, `-uid`, `-gid`, `-inum` and `-links`.

`-perm` is the exception. Its leading `-` and `/` select all-bits and any-bit matching, not less-than and greater-than (section 13). Mixing the two conventions up is a common source of silently wrong results.

## 11 · Size and Empty Files

```
find / -xdev -type f -size +100M 2>/dev/null
find / -xdev -type f -size -1k 2>/dev/null
find / -xdev -type f -empty 2>/dev/null
```

Units: `c` bytes, `k` KiB, `M` MiB, `G` GiB. The default unit with no suffix is 512-byte blocks, which surprises everyone once.

The gotcha: find **rounds up** to whole units. `-size -1M` therefore means "rounds up to less than one megabyte," which matches only empty files. For exact sizes use bytes (`-size +1048576c`). The sign works like this: `+n` is greater than, `-n` is less than, and plain `n` is exactly n units after rounding.

For a ranked view, use `-printf`: `find / -xdev -type f -printf '%s %p\n' 2>/dev/null | sort -rn | head -20`.

## 12 · Time

Three timestamps exist on a file, and they mean different things:

- **mtime**: content last modified
- **atime**: last read (unreliable, see below)
- **ctime**: inode last changed (permissions, owner, rename, content). Userland cannot set it, which makes it the most valuable timestamp in forensics.

```
find / -xdev -type f -mtime -1 2>/dev/null          # modified in the last 24h
find / -xdev -type f -mmin -60 2>/dev/null          # modified in the last hour
find / -xdev -type f -ctime -7 2>/dev/null          # inode changed within 7 days
find / -xdev -type f -newer /etc/hostname 2>/dev/null   # newer than a reference file
find / -xdev -type f -newermt '2026-10-01' ! -newermt '2026-10-05' 2>/dev/null
```

The `-mtime n` family counts in whole 24-hour periods and discards fractions. `-mtime +1` means older than **two** days, not one. `-mtime 0` and `-mtime -1` both mean within the last 24 hours. When you need precision, use `-mmin` or `-newermt`. `-daystart` measures from midnight instead of from now.

A warning on atime: most systems mount with `relatime` or `noatime`, so atime is updated rarely or never. Do not build conclusions on it.

## 13 · Permissions and Ownership

`-perm` has three modes, and confusing them is the most common security-search bug:

- `-perm 644` matches **exactly** these bits.
- `-perm -4000` matches files with **all** listed bits set (the other bits are ignored).
- `-perm /6000` matches files with **any** of the listed bits set.

The old `+mode` syntax is gone from modern GNU find. Use `/mode`.

```
find / -xdev -type f -perm -4000 2>/dev/null           # SUID
find / -xdev -type f -perm /6000 2>/dev/null           # SUID or SGID
find / -xdev -type f -perm -0002 2>/dev/null           # world-writable
find / -xdev -type f -user root -perm -0002 2>/dev/null   # root-owned and world-writable
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null       # orphaned ownership
```

Ownership tests: `-user`, `-group`, `-uid`, `-gid`, `-nouser`, `-nogroup`. Access tests `-readable`, `-writable` and `-executable` check access for the *current* user, which answers the real question: can I touch this file as the account I have right now?

## 14 · Inodes, Hard Links and Filesystem Types

These tests look below the filename, at what the filesystem actually stores.

```
find / -xdev -inum 123456 2>/dev/null                 # every name for one inode
find / -xdev -type f -links +1 2>/dev/null            # files with more than one hard link
find / -xdev -samefile /usr/bin/example 2>/dev/null   # other names for the same file
```

A filename is just a directory entry pointing at an inode. `-inum` and `-samefile` find every entry that points at the same one, and `-links +1` finds inodes with more than one name. Hard links only exist within a single filesystem, which is why `-xdev` belongs on these searches.

**Why this matters for security.** A hard link keeps a file's content alive after its original name is removed or replaced. An old copy of a vulnerable SUID binary linked somewhere writable can survive a package update that replaced the original. Modern kernels restrict this with `fs.protected_hardlinks`, but older systems and unusual configurations still turn such cases up. Treat an unexpected extra name for a SUID file as something to explain. Plenty of legitimate files have several links (some package tools and busybox-style binaries), so baseline a clean system first.

**Filesystem types with `-fstype`.** The test matches by the type of filesystem a file lives on:

```
find / -fstype ext4 -type f 2>/dev/null
find /var -maxdepth 1 -printf '%F %p\n'     # print each entry's filesystem type
```

Type names are system-specific. Check yours with `findmnt -o TARGET,FSTYPE` or `df -T`. `-fstype` is only a test: it does not stop find from descending. To skip a filesystem entirely, pair it with `-prune`, as in section 05. Typical prune candidates are `proc`, `sysfs` and network types such as `nfs` and `cifs`. Be careful about pruning `tmpfs` wholesale, because `/tmp` and `/dev/shm` are often tmpfs and are exactly where you want to look.

## 15 · Actions and Safe Output

**Printing.**

```
find / -xdev -type f -name 'passwd*' -ls 2>/dev/null
find /etc -type f -printf '%m %u:%g %s %TY-%Tm-%Td %p\n' 2>/dev/null
```

Useful `-printf` fields:

- `%p` path, `%f` basename, `%h` directory
- `%s` size in bytes, `%m` octal mode, `%M` symbolic mode
- `%u` / `%g` owner and group names, `%U` / `%G` numeric IDs
- `%T@` mtime as epoch seconds, `%C@` ctime, `%A@` atime
- `%i` inode, `%n` hard link count, `%l` symlink target

**Running commands.**

```
find /usr/bin -type f -exec sha256sum {} \;     # one process per file
find /usr/bin -type f -exec sha256sum {} +      # batched, far faster
find /tmp -type f -ok rm {} \;                  # asks before each command
find /srv/app -type f -execdir file {} \;       # runs inside each file's directory
```

Prefer `+` for speed. Prefer `-execdir` over `-exec` when the tree is writable by other users, because it avoids path race conditions.

**Handling awkward filenames.** Newline-delimited output breaks on names containing spaces or newlines, and attackers do create those. Use NUL separators end to end:

```
find / -xdev -type f -print0 2>/dev/null | xargs -0 sha256sum
find / -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 ls -ld
```

**Deleting.** `-delete` is order-sensitive and implies `-depth`.

```
find /tmp -type f -name '*.tmp' -delete       # correct
find /tmp -delete -type f -name '*.tmp'       # deletes everything under /tmp
```

Run the same command with `-print` first, read the output, then swap in `-delete`.

One security note: `-exec` runs arbitrary programs, so an account that can run find as root, or a SUID `find`, effectively has root. That is why find is listed on GTFOBins.

## 16 · Automation Security: Races, sh -c and Safe Deletion

find is easy to use safely on your own laptop and surprisingly easy to turn into a privilege-escalation primitive inside a root cron job. The difference is who controls the filesystem it walks.

**Check-then-act races.** find decides a file matches, and only later does your command act on it. If another user can change the tree in between, the command may act on something else. Consider a root-owned cleanup job:

```
find /tmp/uploads -type f -mtime +1 -exec rm {} \;
```

If the owner of `/tmp/uploads` can swap a directory for a symlink in the gap between the match and the `rm`, the privileged process can be steered into deleting files elsewhere.

GNU's security notes recommend `-execdir`, and `-delete` over `-exec rm`, in shared writable trees, because they operate relative to the directory being processed instead of on full path strings. Prefer them, run the job as the least-privileged user that can do it, and avoid `-L` in trees other people can write to, since symlinks are what the attacker uses.

**`-execdir` has a precondition.** It refuses to run if `PATH` contains `.`, an empty component or any relative directory. Keep `PATH` to absolute, trusted directories in scripts.

> [!WARNING]
> **Never splice filenames into shell text.** Filenames are attacker-controlled data. This turns them into code:

```
# Dangerous: the filename becomes part of a shell command
find . -type f -exec sh -c "wc -l {}" \;

# Safe: the filename arrives as an argument
find . -type f -exec sh -c 'wc -l "$@"' sh {} +
```

In the safe form, the lone `sh` after the script fills `$0`, and every matched file arrives in `"$@"`. A file named `x; id` is just a name there.

**Leading dashes.** A file named `-rf` can masquerade as an option. Starting from `.` or an absolute path prefixes results with `./` or `/`, which defuses it. When names arrive through a pipe, end option parsing explicitly: `xargs -0 rm --`.

> [!WARNING]
> **An unset variable can become the whole current directory.** GNU find with no starting point searches `.`, so this destroys the working directory when `$DIR` is empty:

```
find $DIR -type f -delete
```

Quote variables, use `${DIR:?}` so the script aborts when it is empty, and never leave a destructive command depending on a value you did not check.

**A safe deletion routine.**

1. Run the exact command with `-print` and read the output.
2. Count it with `... -print | wc -l`. Does the number match your expectation?
3. Put `-delete` last, after every test, and add `-xdev` and `-type f`.
4. To keep a record, use `-print -delete`, which prints each path as it removes it.
5. For one-off interactive cleanups, `-ok` and `-okdir` work like `-exec` and `-execdir` but ask for a `y` before each command. They are for people at a terminal, not for automation.

## 17 · Combining find with grep, xargs and Other Tools

find answers which files have these properties. grep answers which files contain this data. Keeping those jobs separate is the Unix design, and it is also faster: filter by metadata first, then read only the survivors.

```
# Candidates by metadata, content search on the survivors
find /etc -type f -name '*.conf' -exec grep -nH 'Listen' {} +

# Same idea, NUL-safe and parallel across 4 workers
find /var/www -type f \( -name '*.php' -o -name '*.js' \) -print0 | xargs -0 -P4 grep -lI 'api_key'
```

`grep -I` skips binary files, `-l` lists only filenames, `-n` adds line numbers, and `-H` forces the filename even when grep receives a single file. With `-exec ... {} +`, find may hand grep one file in the last batch, which is why `-H` matters.

**Other common partners:**

- `file`, `stat` and `ls -l` describe what find returned: `find /tmp -type f -exec file {} +`
- `sha256sum` fingerprints files: `find /usr/bin -type f -exec sha256sum {} +`
- `sort -z`, `uniq` and `awk` rank or summarize `-printf` output
- `tar` bundles evidence: `find /tmp -type f -mmin -120 -print0 | tar --null -czf tmp_evidence.tgz -T -`

**Loop over results without breaking on odd names.** When you need real shell logic per file, read NUL-delimited names:

```
while IFS= read -r -d '' f; do
  printf '%s\t%s\n' "$(stat -c %a "$f")" "$f"
done < <(find /etc -type f -print0)
```

This is the robust replacement for `for f in $(find ...)`, which splits on whitespace and expands globs inside filenames.

**Forensic caution.** Reading a file can update its access time on filesystems that track it, and copying evidence from a live system changes the system. When the evidence matters, image the disk or mount it read-only first, then run these commands against the mount.

## 18 · Security Use Cases

Each of these is a reconnaissance or triage pattern for authorized work: pentests, CTFs, hardening reviews and incident response.

**A. Privilege escalation recon.**

```
# SUID and SGID binaries
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null

# Scripts or configs that root runs but you can write
find /etc/cron* /etc/init.d /etc/systemd -type f -writable 2>/dev/null

# World-writable files owned by root
find / -xdev -type f -user root -perm -0002 2>/dev/null
```

The signal is in the diff against a normal system. `passwd`, `sudo`, `su`, `mount` and `ping` are expected. A SUID `vim`, `python` or `find` is not, and each unusual hit should be checked against GTFOBins. find cannot see file capabilities, so pair it with `getcap -r / 2>/dev/null`.

**B. Secrets and credentials.**

```
find / -xdev -type f \( -name 'id_rsa*' -o -name '*.pem' -o -name '.env' -o -name 'wp-config.php' -o -name '*.kdbx' -o -name '.bash_history' \) 2>/dev/null
```

**C. Persistence and tampering.**

```
# Executables in directories that should not hold them
find /tmp /var/tmp /dev/shm -type f -perm /111 -ls 2>/dev/null

# Files changed recently, excluding noisy trees
find / -xdev -type f -mmin -120 -not -path '/var/log/*' 2>/dev/null

# Hidden files in unexpected places
find /tmp /var/www -type f -name '.*' 2>/dev/null
```

**D. Incident response timeline.** Build a sortable timeline from ctime, which is much harder to forge than mtime:

```
find / -xdev -type f -printf '%C@ %T@ %u %m %p\n' 2>/dev/null | sort -n > timeline.txt
```

**E. Integrity baseline and diff.**

```
find -H /bin /sbin /usr/bin /usr/sbin -type f -exec sha256sum {} + 2>/dev/null | sort -k2 > hashes_baseline.txt
# later
sha256sum -c hashes_baseline.txt 2>/dev/null | grep -v ': OK$'
```

> [!CAUTION]
> If the host may be compromised, the `find`, `sha256sum` and libc on it are untrusted. Run trusted copies from read-only media, or mount the disk read-only on a clean machine.

## 19 · Credential and Sensitive-File Discovery

The goal of this pass is to locate where credentials live, so they can be reported and protected. The secrets one-liner in section 18 is the starting point. This goes wider and adds permission checks, which is where the findings usually are.

**Keys and tokens:**

```
# SSH private keys and authorized_keys
find /home /root -type f \( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name 'authorized_keys' \) -ls 2>/dev/null

# Private keys readable by group or others (SSH itself would reject these)
find /home /root -type f -name 'id_*' ! -name '*.pub' -perm /077 -ls 2>/dev/null

# Cloud, container and VCS credentials
find /home /root -type f \( -path '*/.aws/credentials' -o -path '*/.kube/config' -o -path '*/.docker/config.json' -o -name '.git-credentials' -o -name '.netrc' \) -ls 2>/dev/null
```

**History and shell artifacts.** Shell history often holds pasted passwords and tokens:

```
find /home /root -type f -name '.*history*' -ls 2>/dev/null
```

**Forgotten copies.** Backups, editor leftovers and dumps routinely outlive the hardening applied to the original:

```
find / -xdev -type f \( -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*~' -o -name '*.swp' -o -name '*.sql' \) 2>/dev/null
```

**Hidden files.** Names starting with `.` are hidden by convention and nothing more. Listing them is useful: `find /home -type f -name '.*'`. Developers, shells, editors and package managers create plenty of legitimate ones, so hidden does not mean malicious.

**Web application trees.** Web roots collect backups, configuration and uploaded files, and a recently modified script there deserves a look:

```
find /var/www -type f \( -name '*.bak' -o -name '*.old' -o -name '*.zip' -o -name '.env' \) -ls 2>/dev/null
find /var/www -type f -name '*.php' -mtime -7 -ls 2>/dev/null
find /var/www -type f -name '*.php' -exec grep -nH -E 'eval\(|base64_decode\(' {} +
```

The last command matches common obfuscation functions. Plenty of legitimate code uses them too, so every hit is a lead to read, not a verdict.

**Handling what you find.** In an authorized assessment, record the path, owner, mode and timestamp, then stop. Do not copy or print the contents of credential files into reports or tickets. A finding such as "private key readable by group" or "cloud credentials in a world-readable home directory" is complete without the secret itself.

## 20 · Persistence Hunting: Cron, systemd and Startup Files

An attacker who wants to survive a reboot has to write something the system runs automatically. Those places are a short, finite list, which makes this one of the highest-value uses of find during incident response. Paths vary by distribution, so verify them on the host you are examining.

**Cron:**

```
find /etc/cron* /var/spool/cron -type f -ls 2>/dev/null
find /etc/cron* /var/spool/cron -type f -mtime -7 -ls 2>/dev/null
```

The shell expands `/etc/cron*` into `/etc/crontab`, `/etc/cron.d`, `/etc/cron.daily` and the rest. User crontabs live in `/var/spool/cron/crontabs` on Debian-family systems and in `/var/spool/cron` on Red Hat-family systems.

**systemd:**

```
find /etc/systemd /usr/lib/systemd /lib/systemd -type f \( -name '*.service' -o -name '*.timer' \) -mtime -7 -ls 2>/dev/null
find /home /root -path '*/.config/systemd/user/*' -type f -ls 2>/dev/null
```

The second command catches per-user units, a quiet persistence route that needs no root.

**Legacy startup, shell profiles and sudo drop-ins:**

```
find /etc/init.d /etc/rc*.d /etc/profile.d /etc/sudoers.d -type f -mtime -7 -ls 2>/dev/null
find /home /root -maxdepth 2 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.bash_profile' \) -mtime -7 -ls 2>/dev/null
ls -l /etc/ld.so.preload 2>/dev/null
```

That last file normally does not exist. If it does, read it: it forces a shared library into every dynamically linked process, a classic userland rootkit mechanism.

**Turn candidates into conclusions.** find shows what changed, not what runs. Correlate with the system's own view:

```
systemctl list-timers --all
systemctl list-unit-files --state=enabled
journalctl --since '2026-10-01'
```

For package-managed paths, a verification pass beats eyeballing timestamps: `dpkg -V` on Debian-family systems, `rpm -Va` on Red Hat-family systems, or `debsums -c`. A package-owned file that fails verification, or an unowned file inside a system unit directory, deserves attention.

## 21 · Writable Locations, Orphaned Files and Capabilities

Privilege escalation through the filesystem usually reduces to one question: can a low-privilege account modify something a privileged process trusts? These queries enumerate the candidates.

**Writable directories.** Directory write permission controls who can create, delete and rename entries inside it, so directories often matter more than files. World-writable directories without the sticky bit are the dangerous ones, because any user can delete or replace anyone else's files there. `/tmp` is world-writable too, but its sticky bit prevents that.

```
find / -xdev -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null    # world-writable, no sticky bit: investigate
find / -xdev -type d -perm -0002 -perm -1000 -ls 2>/dev/null      # world-writable with sticky bit: expected
```

**Root-owned files that others can write:**

```
find / -xdev -type f -user root \( -perm -0002 -o -perm -0020 \) -ls 2>/dev/null
```

This matches root-owned files writable by everyone or by their group. Narrow the results to files something privileged actually executes or reads: scripts called from cron or systemd units, libraries and configuration files.

**Writable entries in `PATH`.** If a directory in the `PATH` of a privileged process is writable by you, you can plant a command that shadows a real one:

```
for d in ${PATH//:/ }; do find -H "$d" -maxdepth 1 -writable 2>/dev/null; done
```

`-writable` asks the kernel whether the current user can write, so run it as the account you are assessing.

**SUID and SGID files in unusual places.** Standard SUID binaries live in a small set of system directories. A hit elsewhere deserves a closer look:

```
find / -xdev -type f -perm -4000 ! -path '/usr/*' ! -path '/bin/*' ! -path '/sbin/*' -ls 2>/dev/null
```

**Orphaned ownership.** Files whose UID or GID maps to no current account:

```
find / -xdev \( -nouser -o -nogroup \) -ls 2>/dev/null
```

These are common after account deletion, restores, container extraction and migrations, so context matters. They are also worth noting because a new account created later with the same numeric ID would silently inherit them.

**File capabilities.** Capabilities grant specific root powers to a binary without making it SUID. They live in extended attributes, which find cannot display, so use `getcap`:

```
getcap -r / 2>/dev/null
```

A capability such as `cap_setuid` on an interpreter or general-purpose tool is a privilege-escalation path in its own right. Check any hit against GTFOBins.

Every result here is a candidate. A world-writable file is not automatically exploitable, a SUID binary is not automatically abusable, and an unusual owner is not automatically malicious. The finding exists only once you can show who can write it and which privileged process consumes it.

## 22 · Incident Response Workflow

Incident response with find follows one rule: observe and preserve first, interpret second. The workflow narrows from a time window down to a handful of artifacts you can explain.

**1. Fix the clock.** Timestamps are comparable only if everyone reads them the same way. Set UTC for the whole session, since `-newermt` and `-printf` times use the local timezone:

```
export TZ=UTC
WINDOW='2026-10-01 14:00'
```

Then decide which timestamp to trust:

| Timestamp | find tests | Meaning | Forensic value |
| --- | --- | --- | --- |
| mtime | `-mtime`, `-mmin`, `-newermt` | content last changed | Easy to forge with `touch` |
| ctime | `-ctime`, `-cmin`, `-newerct` | inode last changed | Cannot be set directly from userland, so it is hard to forge |
| atime | `-atime`, `-amin`, `-newerat` | last read | Unreliable under `relatime` or `noatime` |

Where the filesystem records it, a birth time is also available to `-printf` as `%B`. A file with an old mtime but a recent ctime has either had its timestamps tampered with or had its metadata changed since. That mismatch alone is a lead.

**2. Work outward in layers.** Start where attackers stage tools, then move to where they persist:

```
find /tmp /var/tmp /dev/shm -type f -newermt "$WINDOW" -ls 2>/dev/null
find /etc /usr/local /opt -type f -newermt "$WINDOW" -ls 2>/dev/null
find / -xdev -type f -perm /111 -newermt "$WINDOW" -ls 2>/dev/null
find / -xdev -type f \( -name '*.sh' -o -name '*.py' -o -name '*.pl' \) -newermt "$WINDOW" -ls 2>/dev/null
```

Run the ctime variant (`-newerct`) over the same paths too. Anything with a recent ctime and an old mtime goes on the list.

**3. Capture metadata in a form you can sort and diff:**

```
find /tmp /var/tmp /dev/shm -type f -newermt "$WINDOW" \
  -printf '%p|%s|%u|%g|%m|%A+|%T+|%C+\n' 2>/dev/null | tee candidates.psv
```

**4. Identify and fingerprint, without executing anything:**

```
find /tmp /var/tmp /dev/shm -type f -newermt "$WINDOW" -exec file {} + 2>/dev/null
find /tmp /var/tmp /dev/shm -type f -newermt "$WINDOW" -exec sha256sum {} + 2>/dev/null | tee candidates.sha256
```

The hashes let you check candidates against threat-intelligence sources and compare across hosts.

**5. Look for running processes whose binary no longer exists.** Malware often deletes itself after launch:

```
ls -l /proc/*/exe 2>/dev/null | grep deleted
```

**6. Correlate and record.** Match the file times against authentication logs, `last`, `journalctl`, `ss -tulpn` and the process list. Keep a transcript of every command you ran (`script` or `tee`), plus the host, the user and the UTC time. A finding you cannot reproduce from your notes is not evidence.

**Ground rules.** Prefer trusted copies of `find`, `sha256sum` and `file` from read-only media, because on a compromised host the local binaries and libraries may lie. Write output to external storage, not to the evidence disk. If the case may go further, image the disk first and do this work on the image.

## 23 · Related Tools

- **locate / plocate** gives instant indexed filename search. It is stale by design, so refresh with `updatedb`. https://plocate.sesse.net/
- **fd** is a faster, friendlier file finder with sane defaults. It skips hidden and git-ignored files unless you pass `-H -I`, so it is not a drop-in replacement. https://github.com/sharkdp/fd
- **ripgrep** (`rg`) searches file contents quickly, and `rg --files` lists files. Use find to narrow, then rg or `grep -r` to read.
- **getcap** lists file capabilities that find cannot see.
- **GTFOBins** tells you what an unusual SUID or sudo-allowed binary can be abused for. https://gtfobins.github.io/
- **LinPEAS** (PEASS-ng) automates many of these checks. Learn the underlying find patterns first so you can read its output critically. https://github.com/peass-ng/PEASS-ng
- **AIDE, Tripwire, debsums, `rpm -Va`** are proper integrity monitors. They beat a hand-rolled hash baseline for ongoing use.
- **auditd and inotifywait** watch in real time, where find only takes snapshots.
- **file, strings, sha256sum and YARA** are the triage tools you run on whatever find returns.

## 24 · Performance

Walking a full filesystem is I/O-bound. The levers that matter:

- **Put cheap, selective tests first.** `-type f` and `-name` cost almost nothing. `-exec` costs a process. Tests that fail early skip everything after them.
- **Reduce the tree.** `-xdev`, `-prune`, `-maxdepth` and explicit starting points beat any micro-optimization.
- **Batch commands** with `-exec ... {} +` or `-print0 | xargs -0`. Add `xargs -P4` to parallelize hashing.
- **Stop early** with `-quit` when you only need the first match.
- **Be polite on production:** `nice -n 19 ionice -c3 find / -xdev -type f ...` keeps the walk from starving real workloads.
- **Use `-O3`** to let GNU find reorder tests by estimated cost. `-D opt` shows what it did.

## 25 · Full Flag Reference

**Global options**

- `-P` / `-H` / `-L` symlink handling
- `-maxdepth N` / `-mindepth N` depth limits
- `-xdev` / `-mount` stay on one filesystem
- `-depth` process contents before the directory
- `-daystart` measure days from midnight
- `-regextype TYPE` choose regex flavor
- `-ignore_readdir_race` quiet errors for files that vanish mid-walk
- `-D opts` / `-Olevel` debug and optimization

**Tests**

- `-type`, `-xtype` file type
- `-name`, `-iname`, `-path`, `-ipath`, `-regex`, `-iregex` name matching
- `-size`, `-empty` size
- `-mtime`, `-atime`, `-ctime`, `-mmin`, `-amin`, `-cmin`, `-newer`, `-newerXY` time
- `-perm`, `-user`, `-group`, `-uid`, `-gid`, `-nouser`, `-nogroup` access control
- `-readable`, `-writable`, `-executable` effective access
- `-links`, `-inum`, `-samefile` inode and hard link tests
- `-lname` symlink target
- `-fstype` filesystem type
- `-context` SELinux label

**Actions**

- `-print`, `-print0`, `-ls`, `-printf`, `-fprint`, `-fprintf`
- `-exec ... ;` / `-exec ... +`, `-execdir`, `-ok`, `-okdir`
- `-delete`
- `-prune`
- `-quit`

**Operators**

- `!` / `-not`, `-a` / `-and`, `-o` / `-or`, `\( \)`, `,`

## 26 · Real Methodology: Putting It Together

1. **Scope the walk.** Run `findmnt`, decide which mounts matter, and set `-xdev` plus explicit starting points.
2. **Count before you collect.** `| wc -l` tells you whether you are about to print 80,000 lines or 8 million.
3. **Start broad, then add predicates.** `-type f`, then owner, then permissions, then time. Each test removes noise.
4. **Rank, do not just list.** Use `-printf` with `sort` to put the largest, newest or most privileged files on top.
5. **Triage hits.** Hash them, run `file` and `strings`, and compare against a known-good system or package manager data.
6. **Save the evidence.** Write results to a file with `-fprint` or a redirect, with the date in the filename, so the scan can be diffed later.
7. **Re-run read-only first.** Every `-exec` and `-delete` command gets a `-print` dry run before it gets teeth.

## 27 · Building Queries in Layers

When a question gets complicated, do not write the final command in one go. Translate the question first, then build the command one layer at a time and look at the output after each.

| Question | Component | find piece |
| --- | --- | --- |
| Where should it look? | starting points, depth, boundaries | `/tmp`, `-maxdepth`, `-xdev`, `-prune` |
| What kind of object? | type | `-type f`, `-type d`, `-type l` |
| Which name or path? | name tests | `-name`, `-iname`, `-path`, `-regex` |
| When? | time tests | `-mtime`, `-mmin`, `-newermt`, `-ctime` |
| How big? | size tests | `-size`, `-empty` |
| Whose? | ownership tests | `-user`, `-group`, `-uid`, `-nouser` |
| With what access? | mode and access tests | `-perm`, `-writable`, `-executable` |
| How do conditions combine? | operators | implicit AND, `-o`, `!`, `\( \)` |
| What happens to matches? | actions | `-print`, `-ls`, `-printf`, `-exec`, `-delete` |

Take a concrete question: which executable regular files under `/tmp` changed in the last hour? Build it up:

```
find /tmp                                    # where
find /tmp -type f                            # only regular files
find /tmp -type f -mmin -60                  # changed in the last hour
find /tmp -type f -mmin -60 -perm /111       # executable by someone
find /tmp -type f -mmin -60 -perm /111 -ls   # show full metadata
```

Each step either removes noise or exposes a wrong assumption while the output is still small. The final command is rarely the one you would have written blind. For anything destructive, the last step is the one you add after reading the output of all the others.

## 28 · Command Cheat Sheet

The queries worth keeping in your shell history. Each stays on one filesystem with `-xdev`; drop it when you need mounted volumes.

| Goal | Command |
| --- | --- |
| All regular files on the root filesystem | `find / -xdev -type f 2>/dev/null` |
| By name pattern | `find / -xdev -type f -name '*.conf' 2>/dev/null` |
| Case-insensitive name | `find / -xdev -type f -iname 'password*' 2>/dev/null` |
| Modified in the last hour | `find / -xdev -type f -mmin -60 2>/dev/null` |
| Changed since a date | `find / -xdev -type f -newermt '2026-10-01' 2>/dev/null` |
| Larger than 500 MiB | `find / -xdev -type f -size +500M 2>/dev/null` |
| Empty files | `find / -xdev -type f -empty 2>/dev/null` |
| SUID files | `find / -xdev -type f -perm -4000 -ls 2>/dev/null` |
| SGID files | `find / -xdev -type f -perm -2000 -ls 2>/dev/null` |
| SUID or SGID | `find / -xdev -type f -perm /6000 -ls 2>/dev/null` |
| World-writable files | `find / -xdev -type f -perm -0002 -ls 2>/dev/null` |
| World-writable directories, no sticky bit | `find / -xdev -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null` |
| Executables in temp directories | `find /tmp /var/tmp /dev/shm -type f -perm /111 -ls 2>/dev/null` |
| Files with no owner | `find / -xdev -nouser -ls 2>/dev/null` |
| Broken symlinks | `find / -xdev -xtype l 2>/dev/null` |
| Private SSH keys | `find /home /root -type f -name 'id_*' ! -name '*.pub' -ls 2>/dev/null` |
| Files with multiple hard links | `find / -xdev -type f -links +1 2>/dev/null` |
| First match only | `find / -xdev -name ssh_config -print -quit 2>/dev/null` |
| Fingerprint a directory | `find /usr/bin -type f -exec sha256sum {} +` |

For the largest files, print sizes with `-printf '%s %p\n'` and sort numerically in reverse with `sort -rn`. To hand results to another tool safely, end the command with `-print0` and read the output with `xargs -0`.

## 29 · Common Mistakes

- **Forgetting `2>/dev/null` and drowning real results in permission errors**, or hiding stderr when you actually needed to see what was unreadable.
- **Writing `-name 'a' -o -name 'b' -print`** without parentheses, so `-print` only applies to the last alternative.
- **Leaving globs unquoted**, so the shell expands them against the current directory.
- **Mixing up `-perm 4000`, `-perm -4000` and `-perm /4000`.** They are exact, all-bits and any-bit matches.
- **Reading `-size -1M` as "under a megabyte".** Rounding makes it "empty".
- **Trusting `-mtime +1` to mean one day.** It means at least two full days.
- **Putting `-delete` before the tests.** It runs first and deletes everything.
- **Piping into `xargs` without `-print0` and `-0`**, which breaks on spaces and newlines.
- **Scanning `/` without `-xdev` or `-prune`**, then waiting on `/proc` and network mounts.
- **Assuming `-type f` includes symlinks.** It does not, unless you use `-L`.
- **Basing a conclusion on atime.** Most systems barely update it.

Several more pitfalls show up in privileged and incident-response work:

- **Using an unquoted or unset variable as the starting point.** `find $DIR -delete` with an empty `$DIR` runs against the current directory.
- **Putting filenames inside `sh -c` command strings.** Pass them as arguments with `"$@"` instead.
- **Following symlinks with `-L` in trees other users can write to.** The attacker's tool is a symlink.
- **Combining `-prune` with `-delete` or `-depth`.** `-depth` makes `-prune` have no effect.
- **Hiding stderr during an investigation and never reading it.** The errors are a map of what you could not see.
- **Reading `-newermt` and `-printf` times in a different timezone than the logs.** Set `TZ=UTC` when you correlate.
- **Calling a file malicious because it is hidden, world-writable, orphaned or oddly named.** Those are candidates, not conclusions.
- **Running recon against systems you are not authorized to assess.** The commands are read-only, but the access still has to be permitted.

`find / -type f` is not a command to memorize. It is the first sentence of a query language. Once the evaluation model clicks (tests filter, actions consume, operators bind in a fixed order), every security question about files on a Linux box becomes a predicate you can write in one line.

*Reference: GNU findutils manual and find(1) man page, https://www.gnu.org/software/findutils/*

**Researcher:** Sourov Hossen **LinkedIn:** [linkedin.com/in/sourov-hossen-307655351](https://www.linkedin.com/in/sourov-hossen-307655351/) **GitHub:** [github.com/shii9](https://github.com/shii9)
