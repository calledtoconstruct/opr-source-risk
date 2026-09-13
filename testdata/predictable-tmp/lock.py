from pathlib import Path

lock = Path("/tmp/fixture.lock")
lock.write_text("held")
