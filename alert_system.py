import logging
import json
from datetime import datetime


class AlertSystem:

    def __init__(
        self,
        log_file="ids_alerts.log"
    ):

        self.logger = logging.getLogger(
            "IDS_Alerts"
        )

        self.logger.setLevel(
            logging.INFO
        )

        handler = logging.FileHandler(
            log_file
        )

        formatter = logging.Formatter(
            '%(asctime)s - '
            '%(levelname)s - '
            '%(message)s'
        )

        handler.setFormatter(
            formatter
        )

        self.logger.addHandler(
            handler
        )

    def generate_alert(
        self,
        threat,
        packet_info
    ):

        alert = {

            'timestamp':
                datetime.now().isoformat(),

            'threat_type':
                threat['type'],

            'source_ip':
                packet_info.get(
                    'source_ip'
                ),

            'destination_ip':
                packet_info.get(
                    'destination_ip'
                ),

            'source_port':
                packet_info.get(
                    'source_port'
                ),

            'destination_port':
                packet_info.get(
                    'destination_port'
                ),

            'confidence':
                threat.get(
                    'confidence',
                    0.0
                ),

            'details':
                threat
        }

        self.logger.warning(
            json.dumps(alert)
        )

        print(
            "\n!!! ALERT !!!"
        )

        print(
            json.dumps(
                alert,
                indent=4
            )
        )

        if threat.get(
            'confidence',
            0
        ) > 0.8:

            self.logger.critical(

                f"High confidence threat detected: "
                f"{json.dumps(alert)}"

            )