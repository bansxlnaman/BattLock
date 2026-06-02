class CANLogger:

    def __init__(
        self,
        logger,
        metrics
    ):

        self.logger = logger

        self.metrics = metrics

    def log_frame(
        self,
        sender,
        receiver,
        frame,
        latency
    ):

        payload = frame.data.hex()

        self.logger.info(
f"""
[{sender} -> {receiver}]

CAN ID:
{hex(frame.arbitration_id)}

Length:
{len(frame.data)}

Payload:
{payload}

Latency:
{latency:.3f} ms
"""
        )

        self.metrics.record_can(
            len(frame.data),
            latency
        )