import unittest

import pandas as pd

from fraud_engine.normalize import SchemaError, normalize_frame


def frame(**overrides):
    row = {"message_id": "m1", "received_time": "2026-01-05 10:15:00", "source_addr": "SND1",
           "destination_addr": "999120000001", "network": "NET_A", "message_data": "secret body",
           "route_label": "R1"}
    row.update(overrides)
    return pd.DataFrame([row])


class NormalizeTests(unittest.TestCase):
    def test_message_body_is_dropped_everywhere(self):
        r = normalize_frame(frame())
        self.assertNotIn("message_data", r.good.columns)
        self.assertNotIn("secret body", str(r.good.to_dict("records")))

    def test_extra_columns_kept_in_extra(self):
        r = normalize_frame(frame())
        self.assertEqual(r.good.loc[0, "extra"], {"route_label": "R1"})

    def test_naive_time_uses_source_timezone(self):
        r = normalize_frame(frame(received_time="2026-01-05 10:00:00"), source_tz="Asia/Jakarta")
        self.assertEqual(r.good.loc[0, "received_time"], pd.Timestamp("2026-01-05 03:00:00", tz="UTC"))

    def test_offset_time_converted_to_utc(self):
        r = normalize_frame(frame(received_time="2026-01-05T10:00:00+08:00"), source_tz="UTC")
        self.assertEqual(r.good.loc[0, "received_time"], pd.Timestamp("2026-01-05 02:00:00", tz="UTC"))

    def test_destination_normalized(self):
        r = normalize_frame(frame(destination_addr=" +99912-000 0001 "))
        self.assertEqual(r.good.loc[0, "destination_addr"], "999120000001")

    def test_bad_rows_rejected_with_reason_and_line_number(self):
        raw = pd.concat([frame(message_id="a"), frame(message_id="b", received_time="not a time"),
                         frame(message_id="c", destination_addr="12ab"), frame(message_id=""),
                         frame(message_id="a")], ignore_index=True)
        r = normalize_frame(raw)
        self.assertEqual(list(r.good["message_id"]), ["a"])
        got = dict(zip(r.rejected["line_number"], r.rejected["reason"], strict=True))
        self.assertEqual(got, {3: "invalid_received_time", 4: "invalid_destination_addr",
                               5: "missing_message_id", 6: "duplicate_message_id_in_file"})

    def test_missing_required_column_raises(self):
        with self.assertRaises(SchemaError):
            normalize_frame(frame().drop(columns=["network"]))

    def test_oversized_message_id_rejected(self):
        r = normalize_frame(frame(message_id="x" * 65))
        self.assertEqual(r.rejected.loc[0, "reason"], "message_id_too_long")


if __name__ == "__main__":
    unittest.main()
