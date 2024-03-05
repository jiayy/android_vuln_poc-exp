# Acropalypse detection and sanitization tools

You can use the python script `acropalypse_detection.py` or the yara rule `acropalypse_detection.yar` to detect cropped images affected by acropalypse:

```
$ for i in test_imgs/*; do python3 acropalypse_detection.py $i; done
test_imgs/windows10_snipping_tool_1_cropped.png
test_imgs/windows10_snipping_tool_2_cropped.png
test_imgs/windows10_snipping_tool_3_cropped.jpg
test_imgs/windows11_1_cropped.png
test_imgs/windows11_2_cropped.png
test_imgs/windows11_3_cropped.jpg
```

```
$ yara acropalypse_detection.yar -r test_imgs/
warning: rule "acropalypse_jpeg" in acropalypse_detection.yar(31): string "$a" may slow down scanning
acropalypse_jpeg test_imgs//windows11_3_cropped.jpg
acropalypse_png test_imgs//windows10_snipping_tool_1_cropped.png
acropalypse_png test_imgs//windows10_snipping_tool_2_cropped.png
acropalypse_png test_imgs//windows11_2_cropped.png
acropalypse_png test_imgs//windows11_1_cropped.png
acropalypse_jpeg test_imgs//windows10_snipping_tool_3_cropped.jpg
```

The cropped images are valid PNG images that end with an IEND chunk.
But data from the original image remains after this chunk.
The detection script and rule search for another IEND chunk at the end of the file that corresponds to the original image.

You can sanitize affected images using `acropalypse_sanitizer.py`:

```
$ for i in test_imgs/*; do python3 acropalypse_sanitizer.py $i; done
Saving sanitized file as test_imgs/windows10_snipping_tool_1_cropped_sanitized.png
test_imgs/windows10_snipping_tool_1_cropped_sanitized.png has no trailing bytes or original IEND chunk!
This file is not affected by acropalypse.
test_imgs/windows10_snipping_tool_1.png has no trailing bytes or original IEND chunk!
This file is not affected by acropalypse.
Saving sanitized file as test_imgs/windows10_snipping_tool_2_cropped_sanitized.png
test_imgs/windows10_snipping_tool_2_cropped_sanitized.png has no trailing bytes or original IEND chunk!
This file is not affected by acropalypse.
test_imgs/windows10_snipping_tool_2.png has no trailing bytes or original IEND chunk!
This file is not affected by acropalypse.
Saving sanitized file as test_imgs/windows10_snipping_tool_3_cropped_sanitized.jpg
test_imgs/windows10_snipping_tool_3.jpg has no trailing bytes or original EOI marker!
This file is not affected by acropalypse.
Saving sanitized file as test_imgs/windows11_1_cropped_sanitized.png
test_imgs/windows11_1_cropped_sanitized.png has no trailing bytes or original IEND chunk!
This file is not affected by acropalypse.
test_imgs/windows11_1.png has no trailing bytes or original IEND chunk!
This file is not affected by acropalypse.
Saving sanitized file as test_imgs/windows11_2_cropped_sanitized.png
test_imgs/windows11_2_cropped_sanitized.png has no trailing bytes or original IEND chunk!
This file is not affected by acropalypse.
test_imgs/windows11_2.png has no trailing bytes or original IEND chunk!
This file is not affected by acropalypse.
Saving sanitized file as test_imgs/windows11_3_cropped_sanitized.jpg
test_imgs/windows11_3.jpg has no trailing bytes or original EOI marker!
This file is not affected by acropalypse.
```

This script removes the original data after the end of the cropped file making it impossible to recover the original content:

![Hex comparison between sanitized and vulnerable image.](/Screenshot%202023-03-22%20121216.png)

```
$ ls -la test_imgs/
total 1472
drwxrwxr-x 2 octa octa   4096 mar 23 15:08 .
drwxrwxr-x 4 octa octa   4096 mar 22 16:14 ..
-rw-rw-r-- 1 octa octa  45077 mar 22 09:44 windows10_snipping_tool_1_cropped.png
-rw-rw-r-- 1 octa octa   6886 mar 23 15:08 windows10_snipping_tool_1_cropped_sanitized.png
-rw-rw-r-- 1 octa octa  45077 mar 22 09:43 windows10_snipping_tool_1.png
-rw-rw-r-- 1 octa octa  34484 mar 22 09:44 windows10_snipping_tool_2_cropped.png
-rw-rw-r-- 1 octa octa   5065 mar 23 15:08 windows10_snipping_tool_2_cropped_sanitized.png
-rw-rw-r-- 1 octa octa  34484 mar 22 09:44 windows10_snipping_tool_2.png
-rw-rw-r-- 1 octa octa 226987 mar 23 10:18 windows10_snipping_tool_3_cropped.jpg
-rw-rw-r-- 1 octa octa 108791 mar 23 15:08 windows10_snipping_tool_3_cropped_sanitized.jpg
-rw-rw-r-- 1 octa octa 226987 mar 23 10:18 windows10_snipping_tool_3.jpg
-rw-rw-r-- 1 octa octa 195988 mar 22 11:18 windows11_1_cropped.png
-rw-rw-r-- 1 octa octa   5183 mar 23 15:08 windows11_1_cropped_sanitized.png
-rw-rw-r-- 1 octa octa 195988 mar 22 11:16 windows11_1.png
-rw-rw-r-- 1 octa octa 109834 mar 22 11:26 windows11_2_cropped.png
-rw-rw-r-- 1 octa octa   1365 mar 23 15:08 windows11_2_cropped_sanitized.png
-rw-rw-r-- 1 octa octa 109834 mar 22 11:24 windows11_2.png
-rw-rw-r-- 1 octa octa  46318 mar 23 15:02 windows11_3_cropped.jpg
-rw-rw-r-- 1 octa octa  13218 mar 23 15:08 windows11_3_cropped_sanitized.jpg
-rw-rw-r-- 1 octa octa  46318 mar 23 15:02 windows11_3.jpg
```

That is why the size of the sanitized images is much smaller and the cropped images have the same size as the original ones.

These scripts are based on https://gist.github.com/DavidBuchanan314/93de9d07f7fab494bcdf17c2bd6cef02

If you want to try to recover the original screenshots use https://acropalypse.app