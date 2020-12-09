from datetime import datetime
import time


def periodic(period):
    def decorator(func):
        def wrapped(*args, **kwargs):
            while True:
                start = datetime.now()
                func(*args, **kwargs)
                stop = datetime.now()
                duration = (stop - start).total_seconds()
                if duration < period:
                    time.sleep(period - duration)

        return wrapped

    return decorator