PrivacyLens for Linux  -  version @VERSION@
========================================

PrivacyLens finds personal information (Social Security numbers, card
numbers, medical and bank details, and more) stored in files on this
machine, and tells you exactly where it is.

Install (needs root):

    ./install.sh

This installs /usr/local/bin/privacylens, writes starter scan settings to
/etc/privacylens/scan.json, schedules a weekly scan (systemd timer,
Sundays 02:00), and installs the OCR tools through apt/dnf/yum
(add -no-ocr to skip them).

Use it:

    privacylens gui            open the scanner in your browser
    privacylens ~/Documents    scan a folder from the command line
    privacylens status         check that the installation is healthy

Remove it:

    ./uninstall.sh             (or: sudo privacylens uninstall)

Scan settings, saved reports, and the findings log are kept unless you
add -purge.
A full manual is included: "PrivacyLens User Guide.docx".
