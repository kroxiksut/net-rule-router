# NetRuleRouter End-User License Agreement

Agreement revision 1 · 2026-07-16 · applies to pre-alpha builds (0.1.x)

This agreement is made between you (the "User") and the rights holder of
the NetRuleRouter software — **Fyodor Malkov (kroxiksut)**, the author and owner of the
repository <https://github.com/kroxiksut/net-rule-router> (the "Rights
Holder"). By installing, launching, or using the software you confirm
that you have read this agreement and accept its terms. If you do not
agree with the terms, do not use the software.

## 1. What NetRuleRouter is

NetRuleRouter is a program for managing the routing of network traffic
across network connections that are already configured on your computer.
The software is **not** a VPN client, an anonymity tool, a
censorship-bypass tool, or a proxy manager: it does not create new
network connections and does not hide existing ones.

## 2. License

The software is distributed under the free **Mozilla Public License 2.0
(MPL-2.0)**. The full license text is available in the `LICENSE` file
shipped with the software and in the "License" window inside the
application. This agreement does not restrict the rights granted to you
by MPL-2.0; it supplements the license with terms of use and risk
warnings.

The software also includes components owned by third parties, distributed
under their own licenses. In particular, Windows builds include the
**Wintun** network adapter driver (WireGuard LLC), used solely by the
optional "fake-IP" feature; it is shipped as the author's original signed
file and used only through its published interface. The complete list of
third-party components, their licenses, and how to verify them is in the
`THIRD_PARTY_LICENSES.md` file shipped with the software and in the
"Licenses → Third-party components" window inside the application.

## 3. Pre-alpha status

You are using an **early test version**. This means:

- individual features may work incorrectly or not work at all;
- the emergency blocking (kill switch) and leak protection (fail-closed)
  modes have **not been fully verified** — enabling them may lead to a
  partial or complete loss of network access until the mode is disabled
  or the computer is restarted;
- settings and rules may not carry over to future versions;
- file formats and program behavior may change without preserving
  compatibility.

By enabling experimental modes you act **at your own risk**.

## 4. How the software changes your system

The software requires the installation of a background Windows service
(administrator rights are needed). The software modifies the routing
table and creates network traffic filters. All such changes are
**temporary**: they are removed when the service is stopped and do not
survive a computer restart. If anything is left behind, the package ships
a reset script — `scripts\reset-network.ps1` (`scripts/reset-network.sh`
on Linux), run from an elevated console — which removes the routes and
filters the software created. Instructions for a full reset are in the
documentation (section "Internet gone? How to reset everything").

## 5. User responsibilities

The User is solely responsible for:

- complying with the legislation in force in their jurisdiction when
  using the software;
- complying with the terms of service of third-party services and
  networks whose traffic they route (including the terms of their VPN
  provider, telecom operator, or employer — for corporate networks);
- the content of their own rule sets and the consequences of applying
  them;
- backing up important data before using test versions of the software;
- modifying the application's database files with tools other than the
  application itself, and the consequences of doing so — including
  malfunction of the software, incorrect routing of traffic, or loss of
  stored settings.

## 6. No warranty

The software is provided **"as is"**, without any warranties — express
or implied, including warranties of fitness for a particular purpose and
uninterrupted operation. This corresponds to sections 6 and 7 of the
MPL-2.0 license. To the maximum extent permitted by applicable law, the
Rights Holder shall not be liable for any damages arising from the use
of, or inability to use, the software, including loss of network access,
lost profits, and loss of data.

## 7. Privacy

The software runs locally. It does not require registration or user
accounts, does not send telemetry (telemetry is off by default), and
performs no hidden network calls. Diagnostic archives with logs are
created only by an explicit action of the User, and the User decides
whom to share them with.

## 8. Changes to the terms

The Rights Holder may change this agreement in new versions of the
software. The version number of the agreement is stated in its header;
when the terms change, the software will show the agreement again at
startup. Continued use of the new version of the software constitutes
acceptance of the updated terms.

## 9. Terminating use

You may stop using the software at any time: remove the service
(Settings → "Service management" → "Uninstall service") and delete the
program folder. When the service is removed, all routes and filters
created by the software are removed as well.

## 10. Contact

Bug reports and questions: the project page
<https://github.com/kroxiksut/net-rule-router> (Issues section)
or e-mail <fmalkov91@gmail.com>.

---

Russian version: [eula.ru.md](eula.ru.md). In case of discrepancies
between the language versions, the Russian version prevails.
