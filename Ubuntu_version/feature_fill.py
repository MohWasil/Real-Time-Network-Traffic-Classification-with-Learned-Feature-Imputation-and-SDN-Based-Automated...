# feature_fill.py
"""
Feature preparation for Zeek flows.
Group A: features derivable directly from Zeek (safe math).
Group C: left as NaN for later ML imputation.
"""

import math
import numpy as np


def safe_div(a, b):
    """Guarded division: returns 0.0 if denominator <= 0."""
    return float(a) / float(b) if b > 0 else 0.0


def fill_missing(flow):
    """
    Build a dict of all 77 features. 
    Group A fields: derived directly from Zeek conn log.
    Group C fields: initialized as np.nan (to be imputed).
    Inputs:
        flow (dict): parsed Zeek conn log (JSON)
    Returns:
        dict: {feature_name: value, ...}
    """

    # Zeek-native fields
    dur  = float(flow.get("duration", 0.0))
    f_pk = int(flow.get("orig_pkts", 0))
    b_pk = int(flow.get("resp_pkts", 0))
    f_bt = int(flow.get("orig_ip_bytes", 0))
    b_bt = int(flow.get("resp_ip_bytes", 0))
    dst_p = int(flow.get("id.resp_p", 0))

    tot_pk = f_pk + b_pk
    tot_bt = f_bt + b_bt

    # --- Group A (direct Zeek or simple math) ---
    feats = {
        "destinationport": dst_p,
        "flowduration": dur,
        "totalfwdpackets": f_pk,
        "totalbackwardpackets": b_pk,
        "totallengthoffwdpackets": f_bt,
        "totallengthofbwdpackets": b_bt,
        "flowbytess": tot_bt,
        "flowpacketss": tot_pk,
        "averagepacketsize": safe_div(tot_bt, tot_pk),
        "avgfwdsegmentsize": safe_div(f_bt, f_pk),
        "avgbwdsegmentsize": safe_div(b_bt, b_pk),
        "downupratio": safe_div(b_bt, f_bt),
        "subflowfwdpackets": f_pk,
        "subflowfwdbytes": f_bt,
        "subflowbwdpackets": b_pk,
        "subflowbwdbytes": b_bt,
        "initwinbytesforward": float(flow.get("orig_window", 0)),
        "initwinbytesbackward": float(flow.get("resp_window", 0)),
    }

    # --- Group B (requires ML imputation) ---
    # Fill with NaN as placeholders, model will overwrite
    group_c = [
        "fwdpacketlengthmax", "fwdpacketlengthmin", "fwdpacketlengthmean", "fwdpacketlengthstd",
        "bwdpacketlengthmax", "bwdpacketlengthmin", "bwdpacketlengthmean", "bwdpacketlengthstd",
        "flowiatmean", "flowiatstd", "flowiatmax", "flowiatmin",
        "fwdiattotal", "fwdiatmean", "fwdiatstd", "fwdiatmax", "fwdiatmin",
        "bwdiattotal", "bwdiatmean", "bwdiatstd", "bwdiatmax", "bwdiatmin",
        "fwdpshflags", "bwdpshflags", "fwdurgflags", "bwdurgflags",
        "fwdheaderlength", "bwdheaderlength", "fwdpacketss", "bwdpacketss",
        "minpacketlength", "maxpacketlength", "packetlengthmean", "packetlengthstd", "packetlengthvariance",
        "finflagcount", "synflagcount", "rstflagcount", "pshflagcount",
        "ackflagcount", "urgflagcount", "cweflagcount", "eceflagcount",
        "fwdavgbytesbulk", "fwdavgpacketsbulk", "fwdavgbulkrate",
        "bwdavgbytesbulk", "bwdavgpacketsbulk", "bwdavgbulkrate",
        "actdatapktfwd", "minsegsizemin",
        "activemean", "activestd", "activemax", "activemin",
        "idlemean", "idlestd", "idlemax", "idlemin",
        "l7protocol"
    ]

    for feat in group_c:
        feats[feat] = np.nan

    return feats

