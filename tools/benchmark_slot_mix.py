"""Print decision work units rather than treating host time as a result."""

import json

from noticer_core.slot_mix_scale import measure_work_counts

if __name__ == "__main__":
    print(json.dumps(measure_work_counts(), indent=2, sort_keys=True))
