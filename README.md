osmo-hlr - Osmocom HLR Implementation
=====================================

This repository contains a C-language implementation of a GSM *Home
Location Register (HLR)*. It is part of the
[Osmocom](https://osmocom.org/) Open Source Mobile Communications
project.

Warning: While the HLR logical functionality is implemented, OsmoHLR
does not use the ETSI/3GPP TCAP/MAP protocol stack. Instead, a much
simpler custom protocol (GSUP) is used.  This means, OsmoHLR is of
no use outside the context of an Osmocom core network.  You can use
it with [OsmoMSC](https://osmocom.org/projects/osmomsc/wiki),
[OsmoSGSN](https://osmocom.org/projects/osmosgsn/wiki) etc. -
but not directly with third party components.

Homepage
--------

The official homepage of the project is <https://osmocom.org/projects/osmo-hlr/wiki>.

GIT Repository
--------------

You can clone from the official osmo-hlr.git repository using

	git clone https://gitea.osmocom.org/cellular-infrastructure/osmo-hlr

There is a web interface at <https://gitea.osmocom.org/cellular-infrastructure/osmo-hlr>

Documentation
-------------

User Manuals and VTY reference manuals are [optionally] built in PDF form
as part of the build process.

Pre-rendered PDF versions of the current `master` can be found at

* [User Manual](https://ftp.osmocom.org/docs/latest/osmohlr-usermanual.pdf)
* [VTY Reference Manual for osmo-hlr](https://ftp.osmocom.org/docs/latest/osmohlr-vty-reference.pdf)

Forum
-----

We welcome any osmo-hlr related discussions in the
[Cellular Network Infrastructure -> 2G/3G Core Network](https://discourse.osmocom.org/c/cni/2g-3g-cn)
section of the osmocom discourse (web based Forum).

Mailing List
------------

Discussions related to osmo-hlr are happening on the
openbsc@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/openbsc for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Issue Tracker
-------------

We use the [issue tracker of the osmo-hlr project on osmocom.org](https://osmocom.org/projects/osmo-hlr/issues) for
tracking the state of bug reports and feature requests.  Feel free to submit any issues you may find, or help
us out by resolving existing issues.

Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We use a Gerrit based patch submission/review process for managing
contributions.  Please see
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit> for
more details

The current patch queue for osmo-hlr can be seen at
<https://gerrit.osmocom.org/#/q/project:osmo-hlr+status:open>
