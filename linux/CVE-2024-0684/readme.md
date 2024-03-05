# Abstract

**[CVE-2024-0684](https://access.redhat.com/security/cve/cve-2024-0684)**

A vulnerability in the GNU coreutils "split" program allows for a heap buffer overflow with user controlled data.

It was introduced in
[40bf1591bb4362fa91e501bcec7c2029c5f65a43](https://github.com/coreutils/coreutils/commit/40bf1591bb4362fa91e501bcec7c2029c5f65a43#diff-30bc328ab3afa0ab9f17c6e7cf1752d558ae37cf4200e95bbb04c405c2b59518L821)
on 2023-03-04.
A fix has been released with
[c4c5ed8f4e9cd55a12966d4f520e3a13101637d9](https://github.com/coreutils/coreutils/commit/c4c5ed8f4e9cd55a12966d4f520e3a13101637d9)
on 2024-01-17.

Affected versions: `GNU coreutils` `v9.4`; `v9.3`; `v9.2`

Proof of concept:
The `split_me` example file in this repository can be used to trigger a crash in the affected versions.

```bash
split -C 1024 ./split_me
```

This will crash `split` with a segmentation fault (`SIGABRT`).

# Discovery:

I discovered this vulnerability while attempting to automate data extraction from air-gapped systems using QR codes.
QR codes generated with `qrencode` have a capacity of ~4000 characters, so it required a heavy use of `split`.
On one specific test case, split crashed with a segmentation fault.

# Isolation:

As the [GNU coreutils](https://www.gnu.org/software/coreutils/) are open source,
we can use the source to identify the bug, instead of having to reverse engineer a binary.
On open source projects, you want to be as specific in your bug report as possible,
ideally providing the exact commit and line that introduced the bug, as well as a proposed fix.
This allows maintainers to verify your report quickly and shortens response time.

While verifying the bug across different systems,
I noticed that the crash only occurred on relatively recent versions of `split`.
If you have a good and a bad commit,
that allows you to perform a binary search on the commit history,
in order to find the commit that actually introduced the bug.

Git provides a specific tool for this use case: [`git bisect`](https://git-scm.com/docs/git-bisect).
It will automatically suggest commits to test and allow you to mark them as good or bad.
Eventually you end up with the commit that introduced the bug; in our case:

```
commit 40bf1591bb4362fa91e501bcec7c2029c5f65a43
Author: Paul Eggert <eggert@cs.ucla.edu>
Date:   Sat Mar 4 11:42:16 2023 -0800

    split: prefer signed integers to size_t
    
    This allows for better runtime checking with gcc
    -fsanitize=undefined.
    * src/split.c: Include idx.h.
    (open_pipes_alloc, n_open_pipes, suffix_length)
    (set_suffix_length, input_file_size, sufindex, outbase_length)
    (outfile_length, addsuf_length, create, cwrite, bytes_split)
    (lines_split, line_bytes_split, lines_chunk_split)
    (bytes_chunk_extract, ofile_open, lines_rr, main):
    Prefer signed integers (typically idx_t) to size_t.

 src/split.c | 105 ++++++++++++++++++++++++++++++------------------------------
 1 file changed, 52 insertions(+), 53 deletions(-)
```

We can then compile the program (ideally with an address sanitizer),
in order to find the exact line it crashes.
With only ~50 lines to go through,
it becomes easy to identify the bug.
In our case, the crash occurred in a `memcpy()` call with incorrect indices.
And indeed, if we check the area around the `memcpy()` call,
we find a diff that changes index calculations right before:

```
@@ -816,15 +820,10 @@
           /* Update hold if needed.  */
           if ((eoc && split_rest) || (!eoc && n_left))
             {
-              size_t n_buf = eoc ? split_rest : n_left;
+              idx_t n_buf = eoc ? split_rest : n_left;
               if (hold_size - n_hold < n_buf)
-                {
-                  if (hold_size <= SIZE_MAX - bufsize)
-                    hold_size += bufsize;
-                  else
-                    xalloc_die ();
-                  hold = xrealloc (hold, hold_size);
-                }
+                hold = xpalloc (hold, &hold_size, n_buf - (hold_size - n_hold),
+                                -1, sizeof *hold);
               memcpy (hold + n_hold, sob, n_buf);
               n_hold += n_buf;
               n_left -= n_buf;
```

If we roll back these changes and recompile,
`split` processes all our testcases without error.

All that's left, is to go through the logic in order to verify the bug and develop a fix.
