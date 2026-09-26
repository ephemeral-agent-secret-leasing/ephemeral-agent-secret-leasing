from __future__ import annotations

import argparse
import json

from ephemeral_agent_secret_leasing.stats import wilson

p = argparse.ArgumentParser()
p.add_argument("k", type=int)
p.add_argument("n", type=int)
a = p.parse_args()
print(json.dumps(wilson(a.k, a.n).as_dict(), sort_keys=True))
