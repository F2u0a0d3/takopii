/*
 * Takopii Detection Corpus — Master YARA Ruleset
 *
 * Author:  Takopii Framework
 * License: MIT — same as parent Takopii project
 * Source:  Extracted from specimens/BLUETEAM-DETECTION.md
 *
 * Description:
 *   Master include file that imports all Takopii YARA rule files.
 *   Run with: yara -r master.yar <target.apk>
 *
 * Rule inventory (24 rules across 9 files):
 *
 *   sms-stealer.yar          (2)  SMS ContentResolver patterns (with/without androguard)
 *   dropper.yar               (1)  Dropper config-then-download
 *   banker-shape.yar          (1)  Overlay banker A11y + NLS + SMS multi-vector
 *   dga.yar                   (1)  DGA MD5 + Calendar (SharkBot V2.8 shape)
 *   resource-sms.yar          (1)  Resource-externalized SMS stealer
 *   dcl-antiforensics.yar     (1)  DexClassLoader + file deletion anti-forensics
 *   intarray-encoding.yar     (1)  intArrayOf arithmetic-shift string encoding
 *   frontier.yar              (9)  A11y overlay 2032, hidden VNC, NFC relay,
 *                                   residential proxy SOCKS5, SSO MFA auto-approve,
 *                                   Yamux multiplexer, early-init provider,
 *                                   SMS worm spreading, screen-reader ATS traversal
 *   rat-capabilities.yar      (7)  Silent camera, ambient audio, TOTP scrape,
 *                                   call forwarding, factory reset, AV removal,
 *                                   combined RAT shape
 */

include "sms-stealer.yar"
include "dropper.yar"
include "banker-shape.yar"
include "dga.yar"
include "resource-sms.yar"
include "dcl-antiforensics.yar"
include "intarray-encoding.yar"
include "frontier.yar"
include "rat-capabilities.yar"
