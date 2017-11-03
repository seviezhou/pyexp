import logging
import sys

from thirdparty.ansistrm.ansistrm import ColorizingStreamHandler
from lib.core.enums import CUSTOM_LOGGING

logging.addLevelName(CUSTOM_LOGGING.PAYLOAD, "PAYLOAD")
logging.addLevelName(CUSTOM_LOGGING.TRAFFIC_OUT, "TRAFFIC OUT")
logging.addLevelName(CUSTOM_LOGGING.TRAFFIC_IN, "TRAFFIC IN")

LOGGER = logging.getLogger("PyExpLog")

LOGGER_HANDLER = ColorizingStreamHandler(sys.stdout)
LOGGER_HANDLER.level_map[logging.getLevelName("PAYLOAD")] = (None, "cyan", False)
LOGGER_HANDLER.level_map[logging.getLevelName("TRAFFIC OUT")] = (None, "magenta", False)
LOGGER_HANDLER.level_map[logging.getLevelName("TRAFFIC IN")] = ("magenta", None, False)

FORMATTER = logging.Formatter("\r[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")

LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.INFO)