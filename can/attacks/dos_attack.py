from can.can_message import CANMessage

class DoSAttack:

    def flood(self,count=100):

        messages = []

        for _ in range(1000):

            messages.append(
                CANMessage(
                    arbitration_id=0x7FF,
                    data=b"SPAM"
                )
            )

        return messages